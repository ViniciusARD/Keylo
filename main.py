from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from database import Base, engine, SessionLocal
from auth import auth_router
from models import Usuario, LogAcesso
from schemas import UsuarioOut, LogAcessoOut
from dependencies import verificar_token_revogado
from fastapi.openapi.utils import get_openapi

# Criação das tabelas no banco
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Sistema de Autenticação com Logs")

# Configuração do Swagger com suporte a JWT
def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version="1.0.0",
        description="Documentação da API com autenticação JWT (Bearer Token)",
        routes=app.routes,
    )
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",
            "scheme": "bearer",
            "bearerFormat": "JWT"
        }
    }
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]

    app.openapi_schema = openapi_schema
    return app.openapi_schema

app.openapi = custom_openapi
app.include_router(auth_router, prefix="/auth", tags=["auth"])

@app.get("/")
def root():
    return {"msg": "API de autenticação funcionando"}

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.get("/users/{id}", response_model=UsuarioOut)
def read_user(id: int, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return usuario

@app.get("/logs/access", response_model=List[LogAcessoOut])
def get_logs(db: Session = Depends(get_db)):
    return db.query(LogAcesso).all()

@app.get("/me", dependencies=[Depends(verificar_token_revogado)])
def get_profile(usuario=Depends(verificar_token_revogado)):
    return {"id": usuario.id, "nome": usuario.nome, "email": usuario.email}

# uvicorn main:app --reload
# http://127.0.0.1:8000/docs