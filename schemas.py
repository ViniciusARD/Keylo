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
        from_attributes = True  # Atualizado para Pydantic v2

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    senha: str
