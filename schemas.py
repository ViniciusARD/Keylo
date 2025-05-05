from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import pytz

# Obtém o fuso horário de Brasília
brasilia_tz = pytz.timezone("America/Sao_Paulo")

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)
    papel = Column(String, default="usuario")
    data_criacao = Column(DateTime, default=datetime.now(brasilia_tz))
    data_atualizacao = Column(DateTime, default=datetime.now(brasilia_tz))

    logs = relationship("LogAcesso", back_populates="usuario", foreign_keys="[LogAcesso.usuario_id]")
    logs_responsavel = relationship("LogAcesso", back_populates="responsavel", foreign_keys="[LogAcesso.responsavel_id]")

class LogAcesso(Base):
    __tablename__ = "logs_acesso"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    responsavel_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    tipo_evento = Column(String, nullable=False)
    detalhes = Column(String, nullable=True)
    data_evento = Column(DateTime, default=datetime.now(brasilia_tz))
    ip = Column(String, nullable=True)

    usuario = relationship("Usuario", foreign_keys=[usuario_id], back_populates="logs")
    responsavel = relationship("Usuario", foreign_keys=[responsavel_id], back_populates="logs_responsavel")
    
class TokenRevogado(Base):
    __tablename__ = "tokens_revogados"

    id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    token_hash = Column(String)
    data_revogacao = Column(DateTime, default=datetime.now(brasilia_tz))

class TokenRecuperacaoSenha(Base):
    __tablename__ = "tokens_recuperacao_senha"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String, nullable=False, unique=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    usuario = relationship("Usuario")
    criado_em = Column(DateTime, default=datetime.now(brasilia_tz))
    expira_em = Column(DateTime, nullable=False)
    utilizado = Column(Boolean, default=False)
