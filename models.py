from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

# Modelo de entrada para criação de usuário
class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str

# Modelo de saída com dados públicos do usuário
class UsuarioOut(BaseModel):
    id: int
    nome: str
    email: str
    papel: str
    data_criacao: datetime
    data_atualizacao: datetime

    class Config:
        from_attributes = True

# Modelo de retorno dos tokens de autenticação
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Modelo para login
class LoginRequest(BaseModel):
    email: EmailStr
    senha: str

# Modelo de saída para logs de acesso
class LogAcessoOut(BaseModel):
    id: int
    usuario_id: Optional[int]
    responsavel_id: Optional[int]
    tipo_evento: str
    detalhes: Optional[str]
    data_evento: datetime
    ip: Optional[str]

    class Config:
        from_attributes = True

# Modelo para confirmação de redefinição de senha
class ResetConfirm(BaseModel):
    token: str
    nova_senha: str

# Modelo para solicitação de redefinição de senha
class ResetRequest(BaseModel):
    email: EmailStr

# Modelo para solicitar novo access token via refresh token
class RefreshTokenRequest(BaseModel):
    refresh_token: str

# Modelo de saída de token revogado
class TokenRevogadoOut(BaseModel):
    id: int
    usuario_id: int
    token_hash: str
    data_revogacao: datetime

    class Config:
        from_attributes = True

# Modelo de saída para token de recuperação de senha
class TokenRecuperacaoSenhaOut(BaseModel):
    id: int
    token_hash: str
    usuario_id: int
    criado_em: datetime
    expira_em: datetime
    utilizado: bool

    class Config:
        from_attributes = True

# Modelo de saída para refresh token
class RefreshTokenOut(BaseModel):
    id: int
    token_hash: str
    usuario_id: int
    criado_em: datetime
    usado: bool

    class Config:
        from_attributes = True
