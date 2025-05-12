# Importações das dependências necessárias
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from jose import JWTError, jwt
from hashlib import sha256
import pytz
import secrets

# Importação dos schemas, modelos, funções de segurança e dependências
from schemas import Usuario, TokenRecuperacaoSenha, TokenRevogado, RefreshToken
from models import UsuarioCreate, UsuarioOut, LoginRequest, Token, ResetConfirm, ResetRequest
from security import criar_token, hash_senha, verificar_senha, revogar_token, SECRET_KEY, ALGORITHM
from dependencies import verificar_token_revogado, get_db, registrar_log, verificar_permissao, obter_ip_real, validar_senha_complexa

# Instância do roteador para as rotas de autenticação
auth_router = APIRouter()

# Obtém o fuso horário de Brasília
brasilia_tz = pytz.timezone("America/Sao_Paulo")

# Rota para registrar novo usuário
@auth_router.post("/register", response_model=UsuarioOut)
def register(usuario: UsuarioCreate, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)

    # Verificação da complexidade da senha
    validar_senha_complexa(usuario.senha)

    # Verifica se o e-mail já está registrado
    if db.query(Usuario).filter(Usuario.email == usuario.email).first():
        registrar_log(db, tipo_evento="registro_falha_email_duplicado", ip=ip)
        raise HTTPException(status_code=400, detail="Email já registrado")

    # Criação do objeto de usuário
    novo_usuario = Usuario(
        nome=usuario.nome,
        email=usuario.email,
        senha_hash=hash_senha(usuario.senha),  # Hash da senha antes de salvar
        papel="usuario"  # Papel padrão de 'usuário'
    )

    # Tentativa de adicionar o novo usuário ao banco de dados
    try:
        db.add(novo_usuario)
        db.commit()
        db.refresh(novo_usuario)
        registrar_log(db, usuario_id=novo_usuario.id, tipo_evento="registro_sucesso", ip=ip)
    except IntegrityError:
        # Caso ocorra erro de integridade (e-mail duplicado ou dados inválidos)
        raise HTTPException(status_code=400, detail="Erro ao criar usuário")

    # Retorna os dados do usuário recém-criado
    return novo_usuario

# Rota de login
@auth_router.post("/login", response_model=Token)
def login(request: Request, login_data: LoginRequest, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == login_data.email).first()
    ip = obter_ip_real(request)

    # Verifica se o usuário existe e se a senha está correta
    if not usuario or not verificar_senha(login_data.senha, usuario.senha_hash):
        if usuario:
            usuario.tentativas_login_falhas += 1

            # Se o usuário falhar 5 vezes, bloqueia a conta
            if usuario.tentativas_login_falhas >= 5:
                usuario.papel = "inativo"
                registrar_log(db, usuario_id=usuario.id, tipo_evento="usuario_inativado_por_falha", ip=ip)
            
            db.commit()
        
        # Registra a falha de login
        registrar_log(db, tipo_evento="login_falha", ip=ip)
        raise HTTPException(status_code=401, detail="Credenciais inválidas")

    # Caso o usuário esteja inativo, negamos o login
    if usuario.papel == "inativo":
        registrar_log(db, usuario_id=usuario.id, tipo_evento="login_falha_usuario_inativo", ip=ip)
        raise HTTPException(status_code=403, detail="Usuário inativo. Acesso negado.")

    # Zera as tentativas de login falhas em caso de sucesso
    usuario.tentativas_login_falhas = 0

    # Geração do Access Token
    token_data = {"sub": str(usuario.id)}  # Dados do usuário no token
    access_token = criar_token(token_data)

    # Geração do Refresh Token e armazenamento de seu hash no banco
    raw_refresh_token = secrets.token_urlsafe(64)  # Geração de token seguro
    refresh_token_hash = sha256(raw_refresh_token.encode()).hexdigest()  # Hash do token

    novo_refresh = RefreshToken(
        token_hash=refresh_token_hash,
        usuario_id=usuario.id
    )

    db.add(novo_refresh)
    db.commit()

    # Registra o sucesso do login
    registrar_log(db, usuario_id=usuario.id, tipo_evento="login_sucesso", ip=ip)

    # Retorna o Access Token e o Refresh Token para o cliente
    return {
        "access_token": access_token,
        "refresh_token": raw_refresh_token,
        "token_type": "bearer"
    }

# Rota de logout com revogação de token
@auth_router.post("/logout")
def logout(
    request: Request,
    usuario: Usuario = Depends(verificar_token_revogado),  # Verifica se o token do usuário não foi revogado
    db: Session = Depends(get_db)  # Conexão com o banco de dados
):
    ip = obter_ip_real(request)  # Obtém o IP real do usuário
    token = request.headers.get("Authorization").split(" ")[1]  # Extrai o token do cabeçalho da requisição

    try:
        revogar_token(token, usuario.id, db)  # Revoga o token do usuário
        registrar_log(db, usuario_id=usuario.id, tipo_evento="logout_sucesso", ip=ip)  # Registra o evento de logout
        return {"detail": "Logout realizado com sucesso. Token revogado."}
    
    except JWTError:  # Se houver erro ao revogar o token
        registrar_log(db, tipo_evento="logout_falha_token_invalido", ip=ip)  # Registra falha no logout
        raise HTTPException(status_code=401, detail="Token inválido")  # Retorna erro de token inválido

# Rota para renovar o Access Token usando o Refresh Token
@auth_router.post("/refresh-token")
def renovar_token(refresh_token: str, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)  # Obtém o IP real do usuário
    hashed_token = sha256(refresh_token.encode()).hexdigest()  # Cria o hash do refresh token

    # Verifica se o Refresh Token existe no banco de dados e se não foi utilizado
    token_obj = db.query(RefreshToken).filter(RefreshToken.token_hash == hashed_token).first()

    if not token_obj or token_obj.usado:
        registrar_log(db, tipo_evento="refresh_token_invalido", ip=ip)  # Registra falha no uso do refresh token
        raise HTTPException(status_code=401, detail="Refresh token inválido ou já utilizado")

    # Marca o token como utilizado
    token_obj.usado = True
    db.commit()

    usuario = db.query(Usuario).filter(Usuario.id == token_obj.usuario_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")  # Verifica se o usuário existe

    # Geração do novo Access Token
    token_data = {"sub": str(usuario.id)}
    novo_access_token = criar_token(token_data)

    # Geração de um novo Refresh Token
    novo_raw_refresh_token = secrets.token_urlsafe(64)
    novo_hashed_refresh = sha256(novo_raw_refresh_token.encode()).hexdigest()
    novo_token = RefreshToken(
        token_hash=novo_hashed_refresh,
        usuario_id=usuario.id
    )
    db.add(novo_token)
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="refresh_token_utilizado", ip=ip)  # Registra evento de renovação

    return {
        "access_token": novo_access_token,
        "refresh_token": novo_raw_refresh_token,
        "token_type": "bearer"
    }

# Rota para solicitar a redefinição de senha
@auth_router.post("/reset-password/request")
def solicitar_reset_senha(reset_req: ResetRequest, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)  # Obtém o IP real do usuário
    usuario = db.query(Usuario).filter(Usuario.email == reset_req.email).first()  # Verifica se o usuário existe

    if not usuario:
        registrar_log(db, tipo_evento="reset_senha_email_nao_encontrado", ip=ip)  # Registra falha se o e-mail não for encontrado
        return {"detail": "Se o e-mail estiver cadastrado, instruções foram enviadas."}

    # Geração do token de redefinição de senha com validade de 15 minutos
    token_data = {"sub": str(usuario.id)}
    reset_token = criar_token(token_data, timedelta(minutes=15))

    # Hash do token antes de armazenar no banco
    token_hash = sha256(reset_token.encode()).hexdigest()

    # Armazena o token e sua data de expiração no banco de dados
    expira_em = datetime.now(brasilia_tz) + timedelta(minutes=15)
    token_entry = TokenRecuperacaoSenha(
        token_hash=token_hash,
        usuario_id=usuario.id,
        expira_em=expira_em,
    )
    db.add(token_entry)
    db.commit()

    print(f"Token de redefinição de senha para {usuario.email}: {reset_token}")  # Exibe o token gerado (geralmente, para testes)

    registrar_log(db, usuario_id=usuario.id, tipo_evento="reset_senha_solicitado", ip=ip)  # Registra evento de solicitação

    return {"detail": "Token de redefinição de senha gerado. Verifique seu e-mail."}

# Rota para confirmar a redefinição de senha
@auth_router.post("/reset-password/confirm")
def confirmar_reset_senha(reset: ResetConfirm, request: Request, db: Session = Depends(get_db)):
    ip = obter_ip_real(request)  # Obtém o IP real do usuário

    try:
        payload = jwt.decode(reset.token, SECRET_KEY, algorithms=[ALGORITHM])  # Decodifica o token JWT
        usuario_id = int(payload.get("sub"))  # Obtém o ID do usuário do token
    except JWTError:  # Se houver erro ao decodificar o token
        registrar_log(db, tipo_evento="reset_senha_token_invalido", ip=ip)  # Registra erro de token inválido
        raise HTTPException(status_code=400, detail="Token inválido ou expirado")

    # Verifica o token no banco de dados por hash
    token_hash = sha256(reset.token.encode()).hexdigest()
    token_db = db.query(TokenRecuperacaoSenha).filter_by(
        token_hash=token_hash,
        usuario_id=usuario_id
    ).first()

    if not token_db:
        registrar_log(db, tipo_evento="reset_senha_token_nao_encontrado", ip=ip)  # Registra erro se o token não for encontrado
        raise HTTPException(status_code=400, detail="Token inválido")

    if token_db.utilizado:
        registrar_log(db, tipo_evento="reset_senha_token_utilizado", usuario_id=usuario_id, ip=ip)  # Registra erro se o token já foi utilizado
        raise HTTPException(status_code=400, detail="Token já utilizado")

    if datetime.now(brasilia_tz) > token_db.expira_em.replace(tzinfo=brasilia_tz):
        registrar_log(db, tipo_evento="reset_senha_token_expirado", usuario_id=usuario_id, ip=ip)  # Registra erro se o token expirou
        raise HTTPException(status_code=400, detail="Token expirado")

    usuario = db.query(Usuario).filter(Usuario.id == usuario_id).first()  # Recupera o usuário do banco de dados
    if not usuario:
        registrar_log(db, tipo_evento="reset_senha_usuario_nao_encontrado", ip=ip)  # Registra erro se o usuário não for encontrado
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    # Valida a complexidade da nova senha
    validar_senha_complexa(reset.nova_senha)

    # Atualiza a senha do usuário
    usuario.senha_hash = hash_senha(reset.nova_senha)
    usuario.data_atualizacao = datetime.now(brasilia_tz)

    # Move o token utilizado para a tabela de tokens revogados
    token_revogado = TokenRevogado(
        token_hash=token_hash,
        usuario_id=usuario.id,
    )
    db.add(token_revogado)

    # Marca o token como utilizado e salva as alterações no banco de dados
    token_db.utilizado = True
    db.commit()

    registrar_log(db, usuario_id=usuario.id, tipo_evento="reset_senha_concluido", ip=ip)  # Registra o evento de redefinição de senha

    return {"detail": "Senha redefinida com sucesso"}

# Rota para alterar o papel de um usuário
@auth_router.put("/users/{id}/alterar-papel")
def alterar_papel_usuario(
    id: int,  # Identificador do usuário a ter o papel alterado
    novo_papel: str,  # Novo papel que o usuário irá assumir
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão do banco de dados para interação com a tabela de usuários
    usuario: Usuario = Depends(verificar_permissao(["admin"]))  # Verifica se o usuário autenticado tem permissão de 'admin'
):
    # Lista de papéis válidos que um usuário pode ter
    papeis_validos = ["admin", "gerente", "inativo"]
    
    # Verifica se o novo papel é válido
    if novo_papel not in papeis_validos:
        raise HTTPException(
            status_code=400,  # Retorna erro 400 se o papel não for válido
            detail=f"Novo papel inválido. Os papéis permitidos são: {', '.join(papeis_validos)}."
        )

    # Busca o usuário no banco de dados
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()
    
    # Caso o usuário não seja encontrado, retorna um erro 404
    if not db_usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")
    
    # Armazena o papel anterior do usuário
    papel_anterior = db_usuario.papel
    
    # Atualiza o papel do usuário no banco de dados
    db_usuario.papel = novo_papel
    db.commit()  # Confirma as mudanças no banco de dados

    # Obtém o IP do usuário que fez a solicitação
    ip = obter_ip_real(request)

    # Registra um log de alteração do papel do usuário
    registrar_log(
        db=db,
        usuario_id=db_usuario.id,
        responsavel_id=usuario.id,  # ID do usuário que alterou o papel
        tipo_evento="alteracao_papel_usuario",  # Tipo do evento no log
        ip=ip,  # IP da requisição
        detalhes=f"Alterou o papel do usuário ID {id} de '{papel_anterior}' para '{novo_papel}'"  # Detalhes da mudança
    )

    # Retorna uma mensagem de sucesso com o novo papel
    return {"detail": f"Papel do usuário alterado para {novo_papel}"}

# Rota para exclusão de conta conforme LGPD
@auth_router.delete("/users/{id}", status_code=status.HTTP_200_OK)
def delete_user(
    id: int,  # Identificador do usuário a ser excluído
    request: Request,  # Objeto Request para obter informações sobre a requisição
    db: Session = Depends(get_db),  # Sessão do banco de dados para interação com a tabela de usuários
    usuario: Usuario = Depends(verificar_token_revogado),  # Verifica se o token do usuário está revogado
):
    # Obtém o IP da requisição
    ip = obter_ip_real(request)
    
    # Busca o usuário no banco de dados
    db_usuario = db.query(Usuario).filter(Usuario.id == id).first()

    # Se o usuário não for encontrado, retorna um erro 404 e registra o evento
    if not db_usuario:
        registrar_log(
            db=db,
            usuario_id=id,
            responsavel_id=usuario.id,  # ID do responsável pela requisição
            tipo_evento="exclusao_falha_usuario_nao_encontrado",  # Tipo do evento no log
            ip=ip,  # IP da requisição
            detalhes=f"Tentativa de exclusão do usuário ID {id}, mas não foi encontrado."  # Detalhes da falha
        )
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    # Verifica se o usuário autenticado tem permissão para excluir outro usuário
    if usuario.id != id and usuario.papel not in ["admin", "gerente"]:
        raise HTTPException(status_code=403, detail="Permissão negada. Você só pode se autoexcluir.")

    # Se o usuário está se excluindo, define a mensagem como "autoexclusão"
    if usuario.id == db_usuario.id:
        detalhes = f"Usuário ID {usuario.id} se autoexcluiu do sistema."
    else:
        detalhes = f"Usuário ID {usuario.id} excluiu o usuário ID {db_usuario.id}."

    # Exclui o usuário do banco de dados
    db.delete(db_usuario)
    db.commit()  # Confirma a exclusão no banco de dados

    # Registra um log de exclusão do usuário
    registrar_log(
        db=db,
        usuario_id=db_usuario.id,  # ID do usuário excluído
        responsavel_id=usuario.id,  # ID do responsável pela exclusão
        tipo_evento="exclusao_usuario",  # Tipo do evento no log
        ip=ip,  # IP da requisição
        detalhes=detalhes  # Detalhes da exclusão
    )

    # Retorna uma mensagem de sucesso após a exclusão
    return {"detail": "Usuário excluído com sucesso."}