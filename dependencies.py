from fastapi import Depends, HTTPException, Request
from jose import JWTError, jwt
from security import SECRET_KEY, ALGORITHM, hash_token
from models import TokenRevogado, Usuario
from database import SessionLocal

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verificar_token_revogado(request: Request, db=Depends(get_db)):
    auth = request.headers.get("Authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token ausente ou inválido")

    token = auth.split(" ")[1]
    token_hash = hash_token(token)

    if db.query(TokenRevogado).filter_by(token_hash=token_hash).first():
        raise HTTPException(status_code=401, detail="Token revogado")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        usuario_id = int(payload.get("sub"))
        usuario = db.query(Usuario).filter_by(id=usuario_id).first()
        if not usuario:
            raise HTTPException(status_code=401, detail="Usuário não encontrado")
        return usuario
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")
