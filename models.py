from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base

class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)
    papel = Column(String, default="usuario")
    data_criacao = Column(DateTime, default=datetime.utcnow)
    data_atualizacao = Column(DateTime, default=datetime.utcnow)

    logs = relationship("LogAcesso", back_populates="usuario")

class LogAcesso(Base):
    __tablename__ = "logs_acesso"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    tipo_evento = Column(String, nullable=False)
    data_evento = Column(DateTime, default=datetime.utcnow)
    ip = Column(String, nullable=True)

    usuario = relationship("Usuario", back_populates="logs")

class TokenRevogado(Base):
    __tablename__ = "tokens_revogados"

    id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"))
    token_hash = Column(String)
    data_revogacao = Column(DateTime, default=datetime.utcnow)
