from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from jose import JWTError, jwt
import pytz

from schemas import Usuario 
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

    token_data = {"sub": str(usuario.id)}
    access_token = criar_token(token_data)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="login_sucesso", ip=ip)

    return {"access_token": access_token, "token_type": "bearer"}

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

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()
    if not usuario:
        registrar_log(db, tipo_evento="reset_senha_usuario_nao_encontrado", ip=ip)
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    usuario.senha_hash = hash_senha(reset.nova_senha)
    usuario.data_atualizacao = datetime.now(brasilia_tz)
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
