from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError
from datetime import timedelta, datetime
from jose import JWTError, jwt
from typing import List
from database import SessionLocal
from models import Usuario, LogAcesso
from schemas import UsuarioCreate, UsuarioOut, LoginRequest, Token
from security import criar_token, hash_senha, verificar_senha
from fastapi import Header
from security import revogar_token, SECRET_KEY, ALGORITHM
from dependencies import verificar_token_revogado
from models import Usuario

# Inicializando o Router
auth_router = APIRouter()

# Função para obter o banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Função para registrar logs de acesso
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
    db_usuario = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    if db_usuario:
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

# Rota para realizar login
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

# Rota para logout (revogação de token)
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
