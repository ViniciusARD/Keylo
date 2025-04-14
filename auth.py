from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from sqlalchemy.exc import IntegrityError
from datetime import timedelta, datetime
from jose import JWTError, jwt
from typing import List
from database import SessionLocal
from models import Usuario
from schemas import UsuarioCreate, UsuarioOut, LoginRequest, Token
from config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES

# Inicializando o Router, contexto de criptografia e a chave secreta JWT
auth_router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Função para obter o banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Função para gerar o hash da senha
def hash_senha(senha: str) -> str:
    return pwd_context.hash(senha)

# Função para verificar a senha
def verificar_senha(senha: str, hash_senha: str) -> bool:
    return pwd_context.verify(senha, hash_senha)

# Função para gerar o token JWT
def gerar_token(usuario_id: int, expires_delta: timedelta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)) -> str:
    to_encode = {"sub": str(usuario_id)}
    expiracao = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expiracao})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Rota para registrar novo usuário
@auth_router.post("/register", response_model=UsuarioOut)
def register(usuario: UsuarioCreate, db: Session = Depends(get_db)):
    db_usuario = db.query(Usuario).filter(Usuario.email == usuario.email).first()
    if db_usuario:
        raise HTTPException(status_code=400, detail="Email já registrado")
    
    novo_usuario = Usuario(
        nome=usuario.nome,
        email=usuario.email,
        senha_hash=hash_senha(usuario.senha),
        papel="usuario"  # papel padrão como 'usuario'
    )
    try:
        db.add(novo_usuario)
        db.commit()
        db.refresh(novo_usuario)
    except IntegrityError:
        raise HTTPException(status_code=400, detail="Erro ao criar usuário")
    
    return novo_usuario

# Rota para realizar login
@auth_router.post("/login", response_model=Token)
def login(request: LoginRequest, db: Session = Depends(get_db)):
    db_usuario = db.query(Usuario).filter(Usuario.email == request.email).first()
    if not db_usuario or not verificar_senha(request.senha, db_usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Credenciais inválidas")
    
    # Gerar o token JWT
    access_token = gerar_token(usuario_id=db_usuario.id)
    return {"access_token": access_token, "token_type": "bearer"}
