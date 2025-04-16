from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from database import Base, engine, SessionLocal
from auth import auth_router
from models import Usuario, LogAcesso
from schemas import UsuarioOut, LogAcessoOut
from typing import List
from dependencies import verificar_token_revogado
from fastapi.openapi.utils import get_openapi

# Criação das tabelas no banco de dados
Base.metadata.create_all(bind=engine)

# Inicializando o FastAPI
app = FastAPI(title="Sistema de Autenticação com Logs")

# Configuração personalizada do OpenAPI para habilitar JWT no Swagger
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

# Rota protegida com token JWT
@app.get("/me", dependencies=[Depends(verificar_token_revogado)])
def get_profile(usuario=Depends(verificar_token_revogado)):
    return {"id": usuario.id, "nome": usuario.nome, "email": usuario.email}

# uvicorn main:app --reload
# http://127.0.0.1:8000/docs

