from fastapi import APIRouter, Depends, HTTPException, Request, Header, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from jose import JWTError

from database import SessionLocal
from models import Usuario, LogAcesso
from schemas import UsuarioCreate, UsuarioOut, LoginRequest, Token
from security import criar_token, hash_senha, verificar_senha, revogar_token, SECRET_KEY, ALGORITHM
from dependencies import verificar_token_revogado

auth_router = APIRouter()

# Dependência local para obter sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Função para registrar log de acesso
def registrar_log(db: Session, usuario_id: int = None, tipo_evento: str = "login_sucesso", ip: str = None):
    log = LogAcesso(
        usuario_id=usuario_id,
        tipo_evento=tipo_evento,
        data_evento=datetime.utcnow(),
        ip=ip
    )
    db.add(log)
    db.commit()

# Rota para registrar novo usuário
@auth_router.post("/register", response_model=UsuarioOut)
def register(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    if db.query(Usuario).filter(Usuario.email == usuario.email).first():
        registrar_log(db, tipo_evento="registro_falha_email_duplicado", ip="127.0.0.1")
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
        registrar_log(db, usuario_id=novo_usuario.id, tipo_evento="registro_sucesso", ip="127.0.0.1")
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Erro ao criar usuário")

    return novo_usuario

# Rota de login
@auth_router.post("/login", response_model=Token)
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == login_data.email).first()
    ip = request.client.host

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
    ip = request.client.host
    token = request.headers.get("Authorization").split(" ")[1]

    try:
        revogar_token(token, usuario.id, db)
        registrar_log(db, usuario_id=usuario.id, tipo_evento="logout_sucesso", ip=ip)
        return {"detail": "Logout realizado com sucesso. Token revogado."}
    
    except JWTError:
        registrar_log(db, tipo_evento="logout_falha_token_invalido", ip=ip)
        raise HTTPException(status_code=401, detail="Token inválido")

# Rota para exclusão de conta conforme LGPD
@auth_router.delete("/users/{id}", status_code=status.HTTP_200_OK)
def delete_user(
    id: int,
    request: Request,
    usuario: Usuario = Depends(verificar_token_revogado),
    db: Session = Depends(get_db)
):
    ip = request.client.host

    # Verifica se o usuário é dono da conta ou admin
    if usuario.id != id and usuario.papel != "admin":
        registrar_log(db, usuario_id=usuario.id, tipo_evento="exclusao_falha_permissao", ip=ip)
        raise HTTPException(status_code=403, detail="Permissão negada para excluir este usuário.")

    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if not db_usuario:
        registrar_log(db, usuario_id=usuario.id, tipo_evento="exclusao_falha_usuario_nao_encontrado", ip=ip)
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    db.delete(db_usuario)
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="exclusao_sucesso", ip=ip)

    return {"detail": "Usuário excluído com sucesso."}
