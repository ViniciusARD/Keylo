from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from jose import JWTError, jwt
from hashlib import sha256
import pytz
import secrets

from schemas import Usuario, TokenRecuperacaoSenha, TokenRevogado, RefreshToken
from models import UsuarioCreate, UsuarioOut, LoginRequest, Token, ResetConfirm, ResetRequest
from security import criar_token, hash_senha, verificar_senha, revogar_token, SECRET_KEY, ALGORITHM
from dependencies import verificar_token_revogado, get_db, registrar_log, verificar_permissao, obter_ip_real

auth_router = APIRouter()

# Obtém o fuso horário de Brasília
brasilia_tz = pytz.timezone("America/Sao_Paulo")

# Rota para registrar novo usuário
@auth_router.post("/register", response_model=UsuarioOut)
def register(usuario: UsuarioCreate, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)
    if db.query(Usuario).filter(Usuario.email == usuario.email).first():
        registrar_log(db, tipo_evento="registro_falha_email_duplicado", ip=ip)
        raise HTTPException(status_code=400, detail="Email já registrado")

    novo_usuario = Usuario(
        nome=usuario.nome,
        email=usuario.email,
        senha_hash=hash_senha(usuario.senha),
        papel="usuario"
    )

    try:
        db.add(novo_usuario)
        db.commit()
        db.refresh(novo_usuario)
        registrar_log(db, usuario_id=novo_usuario.id, tipo_evento="registro_sucesso", ip=ip)
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Erro ao criar usuário")

    return novo_usuario

# Rota de login
@auth_router.post("/login", response_model=Token)
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == login_data.email).first()
    ip = obter_ip_real(request)

    if not usuario or not verificar_senha(login_data.senha, usuario.senha_hash):
        registrar_log(db, tipo_evento="login_falha", ip=ip)
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    # Geração do Access Token
    token_data = {"sub": str(usuario.id)}
    access_token = criar_token(token_data)

    # Geração do Refresh Token
    raw_refresh_token = secrets.token_urlsafe(64)
    refresh_token_hash = sha256(raw_refresh_token.encode()).hexdigest()

    novo_refresh = RefreshToken(
        token_hash=refresh_token_hash,
        usuario_id=usuario.id
    )
    db.add(novo_refresh)
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="login_sucesso", ip=ip)

    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "bearer"
    }

# Rota de logout com revogação de token
@auth_router.post("/logout")
def logout(
    request: Request,
    usuario: Usuario = Depends(verificar_token_revogado),
    db: Session = Depends(get_db)
):
    ip = obter_ip_real(request)
    token = request.headers.get("Authorization").split(" ")[1]

    try:
        revogar_token(token, usuario.id, db)
        registrar_log(db, usuario_id=usuario.id, tipo_evento="logout_sucesso", ip=ip)
        return {"detail": "Logout realizado com sucesso. Token revogado."}
    
    except JWTError:
        registrar_log(db, tipo_evento="logout_falha_token_invalido", ip=ip)
        raise HTTPException(status_code=401, detail="Token inválido")

@auth_router.post("/refresh-token")
def renovar_token(refresh_token: str, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)
    hashed_token = sha256(refresh_token.encode()).hexdigest()

    token_obj = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_token).first()

    if not token_obj or token_obj.usado:
        registrar_log(db, tipo_evento="refresh_token_invalido", ip=ip)
        raise HTTPException(status_code=401, detail="Refresh token inválido ou já utilizado")

    # Marcar token como usado
    token_obj.usado = True
    db.commit()

    usuario = db.query(Usuario).filter(Usuario.id == token_obj.usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    # Gerar novo Access Token
    token_data = {"sub": str(usuario.id)}
    novo_access_token = criar_token(token_data)

    # (Opcional) Gerar um novo Refresh Token
    novo_raw_refresh_token = secrets.token_urlsafe(64)
    novo_hashed_refresh = sha256(novo_raw_refresh_token.encode()).hexdigest()
    novo_token = RefreshToken(
        token_hash=novo_hashed_refresh,
        usuario_id=usuario.id
    )
    db.add(novo_token)
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="refresh_token_utilizado", ip=ip)

    return {
        "access_token": novo_access_token,
        "refresh_token": novo_raw_refresh_token,
        "token_type": "bearer"
    }

# Solicitar redefinição de senha
@auth_router.post("/reset-password/request")
def solicitar_reset_senha(reset_req: ResetRequest, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)
    usuario = db.query(Usuario).filter(Usuario.email == reset_req.email).first()

    if not usuario:
        registrar_log(db, tipo_evento="reset_senha_email_nao_encontrado", ip=ip)
        return {"detail": "Se o e-mail estiver cadastrado, instruções foram enviadas."}

    token_data = {"sub": str(usuario.id)}
    reset_token = criar_token(token_data, timedelta(minutes=15))

    # Hash do token antes de armazenar
    token_hash = sha256(reset_token.encode()).hexdigest()

    # Armazenar no banco de dados
    expira_em = datetime.now(brasilia_tz) + timedelta(minutes=15)
    token_entry = TokenRecuperacaoSenha(
        token_hash=token_hash,
        usuario_id=usuario.id,
        expira_em=expira_em,
    )
    db.add(token_entry)
    db.commit()

    print(f"Token de redefinição de senha para {usuario.email}: {reset_token}")

    registrar_log(db, usuario_id=usuario.id, tipo_evento="reset_senha_solicitado", ip=ip)

    return {"detail": "Token de redefinição de senha gerado. Verifique seu e-mail."}

# Confirmar redefinição de senha
@auth_router.post("/reset-password/confirm")
def confirmar_reset_senha(reset: ResetConfirm, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)

    try:
        payload = jwt.decode(reset.token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id = int(payload.get("sub"))
    except JWTError:
        registrar_log(db, tipo_evento="reset_senha_token_invalido", ip=ip)
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")

    # Verifica o token na tabela (por hash)
    token_hash = sha256(reset.token.encode()).hexdigest()
    token_db = db.query(TokenRecuperacaoSenha).filter_by(
        token_hash=token_hash,
        usuario_id=usuario_id
    ).first()

    if not token_db:
        registrar_log(db, tipo_evento="reset_senha_token_nao_encontrado", ip=ip)
        raise HTTPException(status_code=400, detail="Token inválido")

    if token_db.utilizado:
        registrar_log(db, tipo_evento="reset_senha_token_utilizado", usuario_id=usuario_id, ip=ip)
        raise HTTPException(status_code=400, detail="Token já utilizado")

    if datetime.now(brasilia_tz) > token_db.expira_em.replace(tzinfo=brasilia_tz):
        registrar_log(db, tipo_evento="reset_senha_token_expirado", usuario_id=usuario_id, ip=ip)
        raise HTTPException(status_code=400, detail="Token expirado")

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        registrar_log(db, tipo_evento="reset_senha_usuario_nao_encontrado", ip=ip)
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    # Atualiza a senha do usuário
    usuario.senha_hash = hash_senha(reset.nova_senha)
    usuario.data_atualizacao = datetime.now(brasilia_tz)

    # Mover o token utilizado para a tabela de tokens revogados
    token_revogado = TokenRevogado(
        token_hash=token_hash,
        usuario_id=usuario.id,
    )
    db.add(token_revogado)

    # Marcar token como utilizado e salvar
    token_db.utilizado = True
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="reset_senha_concluido", ip=ip)

    return {"detail": "Senha redefinida com sucesso"}

# Promover usuário
@auth_router.put("/users/{id}/promote")
def promover_usuario(
    id: int,
    novo_papel: str,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))
):
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    
    papel_anterior = db_usuario.papel
    db_usuario.papel = novo_papel
    db.commit()

    ip = obter_ip_real(request)

    registrar_log(
        db=db,
        usuario_id=db_usuario.id,
        responsavel_id=usuario.id,
        tipo_evento="promocao_usuario",
        ip=ip,
        detalhes=f"Promoveu usuário ID {id} de '{papel_anterior}' para '{novo_papel}'"
    )

    return {"detail": f"Usuário promovido a {novo_papel}"}

# Rota para exclusão de conta conforme LGPD
@auth_router.delete("/users/{id}", status_code=status.HTTP_200_OK)
def delete_user(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_token_revogado),
):
    ip = obter_ip_real(request)
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()

    if not db_usuario:
        registrar_log(
            db=db,
            usuario_id=id,
            responsavel_id=usuario.id,
            tipo_evento="exclusao_falha_usuario_nao_encontrado",
            ip=ip,
            detalhes=f"Tentativa de exclusão do usuário ID {id}, mas não foi encontrado."
        )
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if usuario.id != id and usuario.papel not in ["admin", "gerente"]:
        raise HTTPException(status_code=403, detail="Permissão negada. Você só pode se autoexcluir.")

    if usuario.id == db_usuario.id:
        detalhes = f"Usuário ID {usuario.id} se autoexcluiu do sistema."
    else:
        detalhes = f"Usuário ID {usuario.id} excluiu o usuário ID {db_usuario.id}."

    db.delete(db_usuario)
    db.commit()

    registrar_log(
        db=db,
        usuario_id=db_usuario.id,
        responsavel_id=usuario.id,
        tipo_evento="exclusao_usuario",
        ip=ip,
        detalhes=detalhes
    )

    return {"detail": "Usuário excluído com sucesso."}

