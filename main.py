from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from auth import auth_router
from models import Usuario, LogAcesso
from schemas import UsuarioOut, LogAcessoOut
from typing import List

# Criação das tabelas no banco de dados
Base.metadata.create_all(bind=engine)

# Inicializando o FastAPI
app = FastAPI(title="Sistema de Autenticação com Logs")

# Inclusão das rotas
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# Rota raiz
@app.get("/")
def root():
    return {"msg": "API de autenticação funcionando"}

# Dependência para obter sessão do banco
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Rota para obter dados de um usuário
@app.get("/users/{id}", response_model=UsuarioOut)
def read_user(id: int, db: Session = Depends(get_db)):
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if db_usuario is None:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return db_usuario

# Rota para visualizar os logs de acesso
@app.get("/logs/access", response_model=List[LogAcessoOut])
def get_logs(db: Session = Depends(get_db)):
    return db.query(LogAcesso).all()

# uvicorn main:app --reload
# http://127.0.0.1:8000/docs

