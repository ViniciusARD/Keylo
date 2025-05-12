# Para rodar a aplicação, siga os passos abaixo:
#
# 1. Abra o terminal e navegue até o diretório onde está o arquivo `main.py`.
# 2. Execute o seguinte comando para rodar o servidor:
#    uvicorn main:app --reload
#
# 3. Após o servidor iniciar, abra seu navegador e acesse:
#    http://127.0.0.1:8000/docs
#
# 4. O Swagger UI será exibido, permitindo que você interaja com a API diretamente do navegador.
#
# Observação: O parâmetro `--reload` permite que o servidor reinicie automaticamente

# Importações das dependências necessárias
from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from typing import List
from fastapi.openapi.utils import get_openapi

# Importação dos schemas, modelos, funções de segurança e dependências
from database import Base, engine
from auth import auth_router
from schemas import Usuario, LogAcesso, TokenRevogado, TokenRecuperacaoSenha, RefreshToken
from models import LogAcessoOut, UsuarioOut, TokenRevogadoOut, TokenRecuperacaoSenhaOut, RefreshTokenOut
from dependencies import verificar_token_revogado, registrar_log, get_db, verificar_permissao, obter_ip_real

# Criação das tabelas no banco de dados com o SQLAlchemy
Base.metadata.create_all(bind=engine)

# Criação da instância FastAPI
app = FastAPI(title="Keylo: Sistema de Autenticação com Logs")

# Configuração do Swagger com suporte a JWT
def custom_openapi():
    # Se o esquema OpenAPI já foi gerado, retorna-o diretamente
    if app.openapi_schema:
        return app.openapi_schema

    # Gera o esquema OpenAPI
    openapi_schema = get_openapi(
        title=app.title,
        version="1.0.0",  # Versão da API
        description="Documentação da API com autenticação JWT (Bearer Token)",  # Descrição da API
        routes=app.routes,  # Rotas registradas na API
    )
    
    # Define o esquema de segurança do Swagger para usar Bearer Token (JWT)
    openapi_schema["components"]["securitySchemes"] = {
        "BearerAuth": {
            "type": "http",  # Tipo de autenticação
            "scheme": "bearer",  # Método de autenticação (bearer token)
            "bearerFormat": "JWT"  # Formato do token (JWT)
        }
    }

    # Aplica a segurança em todas as rotas da API
    for path in openapi_schema["paths"]:
        for method in openapi_schema["paths"][path]:
            openapi_schema["paths"][path][method]["security"] = [{"BearerAuth": []}]

    # Atualiza o esquema OpenAPI da aplicação
    app.openapi_schema = openapi_schema
    return app.openapi_schema

# Substitui a função padrão openapi da FastAPI pela nossa função customizada
app.openapi = custom_openapi

# Inclui o roteador de autenticação (auth_router) na aplicação com o prefixo "/auth"
app.include_router(auth_router, prefix="/auth", tags=["auth"])

# Rota principal para verificar se a API está funcionando
@app.get("/")
def root():
    return {"msg": "API de autenticação funcionando"}

# Rota para obter o perfil do usuário autenticado
@app.get("/me", dependencies=[Depends(verificar_token_revogado)])
def get_profile(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    usuario=Depends(verificar_token_revogado),  # Verifica o token de autenticação do usuário
    db: Session = Depends(get_db)  # Sessão de banco de dados para interagir com a tabela de usuários
):
    # Obtém o IP do usuário que está acessando a API
    ip = obter_ip_real(request)
    
    # Registra um log de acesso ao perfil do usuário
    registrar_log(db, usuario_id=usuario.id, tipo_evento="acesso_perfil", ip=ip)
    
    # Retorna os dados do usuário
    return {"id": usuario.id, "nome": usuario.nome, "email": usuario.email}

# Rota para consultar um usuário específico
@app.get("/users/{id}")
def consultar_usuario(
    id: int,  # ID do usuário a ser consultado
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados para interagir com a tabela de usuários
    usuario: Usuario = Depends(verificar_permissao(["admin", "gerente"]))  # Verifica se o usuário é admin ou gerente
):
    # Consulta o usuário pelo ID no banco de dados
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    
    # Se o usuário não for encontrado, lança uma exceção HTTP 404
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    # Obtém o IP do usuário que fez a requisição
    ip = obter_ip_real(request)

    # Registra o evento de consulta ao perfil de um usuário
    registrar_log(
        db=db,
        usuario_id=db_usuario.id,  # ID do usuário que foi consultado
        responsavel_id=usuario.id,  # ID do usuário que fez a consulta (admin ou gerente)
        tipo_evento="consulta_usuario",
        ip=ip,  # IP da requisição
        detalhes=f"Usuário ID {usuario.id} consultou dados do usuário ID {db_usuario.id}"  # Detalhes do evento
    )

    # Retorna as informações do usuário consultado
    return {
        "id": db_usuario.id,
        "nome": db_usuario.nome,
        "email": db_usuario.email,
        "papel": db_usuario.papel,
        "data_criacao": db_usuario.data_criacao,
        "data_atualizacao": db_usuario.data_atualizacao
    }

# Rota para consultar os logs de acesso
@app.get("/logs/access", response_model=List[LogAcessoOut])
def get_logs(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados
    usuario: Usuario = Depends(verificar_permissao(["admin", "gerente"]))  # Verifica se o usuário é admin ou gerente
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Registra o evento de consulta dos logs de acesso
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_logs", ip=ip)
    
    # Retorna todos os logs de acesso registrados no banco
    return db.query(LogAcesso).all()

# Rota para listar todos os usuários
@app.get("/usuarios", response_model=List[UsuarioOut])
def listar_usuarios(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Verifica se o usuário é admin
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Registra o evento de consulta dos usuários
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_usuarios", ip=ip)
    
    # Retorna todos os usuários registrados no banco
    return db.query(Usuario).all()

# Rota para listar tokens revogados
@app.get("/tokens-revogados", response_model=List[TokenRevogadoOut])
def listar_tokens_revogados(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Verifica se o usuário é admin
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Registra o evento de consulta dos tokens revogados
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_tokens_revogados", ip=ip)
    
    # Retorna todos os tokens revogados registrados no banco
    return db.query(TokenRevogado).all()

# Rota para listar tokens de recuperação de senha
@app.get("/tokens-recuperacao", response_model=List[TokenRecuperacaoSenhaOut])
def listar_tokens_recuperacao(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Verifica se o usuário é admin
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Registra o evento de consulta dos tokens de recuperação de senha
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_tokens_recuperacao", ip=ip)
    
    # Retorna todos os tokens de recuperação de senha registrados no banco
    return db.query(TokenRecuperacaoSenha).all()

# Rota para listar refresh tokens
@app.get("/refresh-tokens", response_model=List[RefreshTokenOut])
def listar_refresh_tokens(
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão de banco de dados
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Verifica se o usuário é admin
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Registra o evento de consulta dos refresh tokens
    registrar_log(db, usuario_id=usuario.id, tipo_evento="consulta_refresh_tokens", ip=ip)
    
    # Retorna todos os refresh tokens registrados no banco
    return db.query(RefreshToken).all()


