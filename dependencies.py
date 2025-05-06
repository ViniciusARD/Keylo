from fastapi import Depends, HTTPException, Request, Security
from jose import JWTError, jwt
from security import SECRET_KEY, ALGORITHM, hash_token
from database import SessionLocal
from sqlalchemy.orm import Session
from datetime import datetime
import pytz

from schemas import TokenRevogado, Usuario, LogAcesso

# Obtém o fuso horário de Brasília
brasilia_tz = pytz.timezone("America/Sao_Paulo")

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

# Função para registrar log de acesso
def registrar_log(
    db: Session,
    usuario_id: int = None,                # usuário afetado (por ex: quem foi promovido)
    tipo_evento: str = "login_sucesso",
    ip: str = None,
    responsavel_id: int = None,            # quem realizou a ação (por ex: o admin)
    detalhes: str = None
):
    log = LogAcesso(
        usuario_id=usuario_id,
        responsavel_id=responsavel_id,     # novo campo
        tipo_evento=tipo_evento,
        detalhes=detalhes,                 # novo campo
        data_evento = datetime.now(brasilia_tz),
        ip=ip
    )
    db.add(log)
    db.commit()

def verificar_permissao(papeis_permitidos: list):
    def inner(usuario: Usuario = Depends(verificar_token_revogado)):
        if usuario.papel not in papeis_permitidos:
            raise HTTPException(status_code=403, detail="Permissão negada")
        return usuario
    return inner

# Função utilitária para pegar o IP real
def obter_ip_real(request: Request) -> str:
    x_forwarded_for = request.headers.get('X-Forwarded-For')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.client.host
    return ip
