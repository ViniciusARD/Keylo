from passlib.context import CryptContext
from datetime import datetime, timedelta
from jose import jwt
from hashlib import sha256
from sqlalchemy.orm import Session

from models import TokenRevogado

SECRET_KEY = "seu-segredo-aqui"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verificar_senha(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def hash_senha(password):
    return pwd_context.hash(password)

def criar_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def hash_token(token: str) -> str:
    return sha256(token.encode()).hexdigest()

def revogar_token(token: str, usuario_id: int, db: Session):
    token_hash = hash_token(token)
    revogado = TokenRevogado(token_hash=token_hash, usuario_id=usuario_id)
    db.add(revogado)
    db.commit()
