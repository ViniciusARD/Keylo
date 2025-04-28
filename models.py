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