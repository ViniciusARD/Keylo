# Importações necessárias para definição das tabelas (models)
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base
import pytz

# Define o fuso horário de Brasília para uso nos campos de data e hora
brasilia_tz = pytz.timezone("America/Sao_Paulo")

# ===========================
# Modelo da Tabela: Usuario
# ===========================
class Usuario(Base):
    __tablename__ = "usuarios"
    __table_args__ = {'sqlite_autoincrement': True}  # Garante incremento automático em SQLite

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    nome = Column(String, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    senha_hash = Column(String, nullable=False)  # Armazena senha criptografada
    papel = Column(String, default="usuario")    # Define o nível de acesso (ex: admin, inativo, etc.)
    tentativas_login_falhas = Column(Integer, default=0)  # Contador para bloqueio automático por falhas
    data_criacao = Column(DateTime, default=datetime.now(brasilia_tz))  # Timestamp de criação
    data_atualizacao = Column(DateTime, default=datetime.now(brasilia_tz))  # Timestamp de última atualização

    # Relacionamentos com logs de acesso e tokens
    logs = relationship("LogAcesso", back_populates="usuario", foreign_keys="[LogAcesso.usuario_id]")
    logs_responsavel = relationship("LogAcesso", back_populates="responsavel", foreign_keys="[LogAcesso.responsavel_id]")
    refresh_tokens = relationship("RefreshToken", back_populates="usuario")

# ===========================
# Modelo da Tabela: LogAcesso
# ===========================
class LogAcesso(Base):
    __tablename__ = "logs_acesso"

    id = Column(Integer, primary_key=True, index=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)       # Usuário afetado pela ação
    responsavel_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)   # Quem executou a ação (ex: admin)
    tipo_evento = Column(String, nullable=False)    # Ex: login_sucesso, login_falha, etc.
    detalhes = Column(String, nullable=True)        # Descrição adicional do evento
    data_evento = Column(DateTime, default=datetime.now(brasilia_tz))
    ip = Column(String, nullable=True)              # IP da requisição

    # Relacionamentos bidirecionais com a tabela Usuario
    usuario = relationship("Usuario", foreign_keys=[usuario_id], back_populates="logs")
    responsavel = relationship("Usuario", foreign_keys=[responsavel_id], back_populates="logs_responsavel")

# ===========================
# Modelo da Tabela: TokenRevogado
# ===========================
class TokenRevogado(Base):
    __tablename__ = "tokens_revogados"

    id = Column(Integer, primary_key=True)
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)  # Usuário dono do token
    token_hash = Column(String)                              # Hash do token JWT revogado
    data_revogacao = Column(DateTime, default=datetime.now(brasilia_tz))

# ===========================
# Modelo da Tabela: TokenRecuperacaoSenha
# ===========================
class TokenRecuperacaoSenha(Base):
    __tablename__ = "tokens_recuperacao_senha"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String, nullable=False, unique=True)  # Hash do token de recuperação
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    usuario = relationship("Usuario")                         # Relacionamento com o usuário
    criado_em = Column(DateTime, default=datetime.now(brasilia_tz))
    expira_em = Column(DateTime, nullable=False)              # Data de expiração do token
    utilizado = Column(Boolean, default=False)                # Flag para evitar reuso do token

# ===========================
# Modelo da Tabela: RefreshToken
# ===========================
class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token_hash = Column(String, nullable=False, unique=True)  # Hash do refresh token
    usuario_id = Column(Integer, ForeignKey("usuarios.id"), nullable=True)
    criado_em = Column(DateTime, default=datetime.now(brasilia_tz))
    usado = Column(Boolean, default=False)                    # Indica se o token já foi utilizado

    usuario = relationship("Usuario", back_populates="refresh_tokens")  # Relacionamento com o usuário
