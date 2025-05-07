from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime

class UsuarioCreate(BaseModel):
    nome: str
    email: EmailStr
    senha: str

class UsuarioOut(BaseModel):
    id: int
    nome: str
    email: EmailStr
    papel: str
    data_criacao: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str

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

class ResetConfirm(BaseModel):
    token: str
    nova_senha: str

class ResetRequest(BaseModel):
    email: EmailStr

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class UsuarioOut(BaseModel):
    id: int
    nome: str
    email: str
    papel: str
    data_criacao: datetime
    data_atualizacao: datetime

    class Config:
        orm_mode = True

class TokenRevogadoOut(BaseModel):
    id: int
    usuario_id: int
    token_hash: str
    data_revogacao: datetime  # ← Nome correto agora

    class Config:
        orm_mode = True

class TokenRecuperacaoSenhaOut(BaseModel):
    id: int
    token_hash: str
    usuario_id: int
    criado_em: datetime
    expira_em: datetime
    utilizado: bool

    class Config:
        orm_mode = True

class RefreshTokenOut(BaseModel):
    id: int
    token_hash: str
    usuario_id: int
    criado_em: datetime
    usado: bool

    class Config:
        orm_mode = True