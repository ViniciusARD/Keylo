from fastapi import FastAPI, Depends, HTTPException  # Adicionando Depends e HTTPException
from database import Base, engine
from auth import auth_router  # Importando as rotas
from sqlalchemy.orm import Session
from models import Usuario
from schemas import UsuarioOut
from database import SessionLocal

# Criando o banco de dados
Base.metadata.create_all(bind=engine)

# Inicializando o FastAPI
app = FastAPI()

# Incluindo as rotas de autenticação
app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.get("/")
def root():
    return {"msg": "API de autenticação funcionando"}

# Função para obter o banco de dados
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/users/{id}", response_model=UsuarioOut)
def read_user(id: int, db: Session = Depends(get_db)):
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if db_usuario is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return db_usuario
