from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from fastapi.openapi.utils import get_openapi

from database import Base, engine
from auth import auth_router
from schemas import Usuario, LogAcesso, TokenRevogado, TokenRecuperacaoSenha, RefreshToken
from models import LogAcessoOut, UsuarioOut, TokenRevogadoOut, TokenRecuperacaoSenhaOut, RefreshTokenOut
from dependencies import verificar_token_revogado, registrar_log, get_db, verificar_permissao, obter_ip_real

# Criação das tabelas no banco
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Keylo: Sistema de Autenticação com Logs")

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

@app.get("/me", dependencies=[Depends(verificar_token_revogado)])
def get_profile(
    request: Request,
    usuario=Depends(verificar_token_revogado),
    db: Session = Depends(get_db)
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="acesso_perfil", ip=ip)
    return {"id": usuario.id, "nome": usuario.nome, "email": usuario.email}

@app.get("/users/{id}")
def consultar_usuario(
    id: int,
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # apenas admins
):
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    ip = obter_ip_real(request)

    registrar_log(
        db=db,
        usuario_id=db_usuario.id,         # quem foi consultado
        responsavel_id=usuario.id,        # quem fez a consulta
        tipo_evento="consulta_usuario",
        ip=ip,
        detalhes=f"Usuário ID {usuario.id} consultou dados do usuário ID {db_usuario.id}"
    )

    return {
        "id": db_usuario.id,
        "nome": db_usuario.nome,
        "email": db_usuario.email,
        "papel": db_usuario.papel,
        "data_criacao": db_usuario.data_criacao,
        "data_atualizacao": db_usuario.data_atualizacao
    }

@app.get("/logs/access", response_model=List[LogAcessoOut])
def get_logs(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Apenas admins
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_logs", ip=ip)
    return db.query(LogAcesso).all()

@app.get("/usuarios", response_model=List[UsuarioOut])
def listar_usuarios(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Apenas admins
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_usuarios", ip=ip)
    return db.query(Usuario).all()

# Listar tokens revogados
@app.get("/tokens-revogados", response_model=List[TokenRevogadoOut])
def listar_tokens_revogados(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_tokens_revogados", ip=ip)
    return db.query(TokenRevogado).all()

# Listar tokens de recuperação de senha
@app.get("/tokens-recuperacao", response_model=List[TokenRecuperacaoSenhaOut])
def listar_tokens_recuperacao(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_tokens_recuperacao", ip=ip)
    return db.query(TokenRecuperacaoSenha).all()

# Listar refresh tokens
@app.get("/refresh-tokens", response_model=List[RefreshTokenOut])
def listar_refresh_tokens(
    request: Request,
    db: Session = Depends(get_db),
    usuario: Usuario = Depends(verificar_permissao(["admin"]))
):
    ip = obter_ip_real(request)
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_refresh_tokens", ip=ip)
    return db.query(RefreshToken).all()

# uvicorn main:app --reload
# http://127.0.0.1:8000/docs
