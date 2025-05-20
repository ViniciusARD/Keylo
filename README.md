# 🔐 Keylo — Sistema de Autenticação Segura com FastAPI

Keylo é uma API de autenticação e controle de acesso desenvolvida com FastAPI. O sistema oferece funcionalidades avançadas de segurança, incluindo autenticação via JWT, controle de acesso baseado em papéis (RBAC), redefinição de senha com tokens temporários, revogação de tokens e logging completo de eventos de segurança.

## 📌 Objetivos

- Garantir a autenticação segura de usuários via tokens JWT.
- Controlar o acesso a rotas com base nos papéis atribuídos (RBAC).
- Permitir redefinição de senha via token de recuperação com expiração.
- Registrar eventos importantes de segurança (logins, falhas, revogações).
- Estar em conformidade com os princípios da LGPD e boas práticas de segurança.

## 🛠️ Tecnologias Utilizadas

- Python 3.11
- FastAPI
- SQLite
- SQLAlchemy
- Passlib (hash de senhas)
- PyJWT
- EmailValidator
- Uvicorn (servidor ASGI)

## ⚙️ Funcionalidades

- ✅ Registro de usuários  
- ✅ Login com geração de Access Token e Refresh Token  
- ✅ Proteção de rotas com RBAC  
- ✅ Redefinição de senha com token seguro e expiração  
- ✅ Revogação de tokens (logout)  
- ✅ Bloqueio temporário após múltiplas tentativas de login inválidas  
- ✅ Registro de logs de autenticação e eventos de segurança  
- ✅ Documentação interativa com Swagger (FastAPI Docs)

## 🧱 Estrutura do Projeto

```
keylo/
│
├── main.py                # Ponto de entrada da aplicação
├── models.py              # Definição das tabelas do banco de dados
├── schemas.py             # Schemas Pydantic para entrada e saída de dados
├── auth.py                # Lógica de autenticação e geração de tokens
├── seecurity.py           # Rotas e lógica de registro, login e redefinição
├── promover_user_admin.py # Implementação do RBAC
├── consultar_tabelas.py   # Registro e consulta de logs
├── dependencies.py        # Dependências reutilizáveis
├── database.py            # Conexão e inicialização do SQLite
│
├── requirements.txt
└── README.md
```

## 🔑 Exemplos de Uso

Registro de usuário:

```
POST /register
```

Body:
```json
{
  "email": "user@example.com",
  "password": "SenhaForte123!"
}
```

Login com JWT:

```
POST /login
```

Body:
```json
{
  "email": "user@example.com",
  "password": "SenhaForte123!"
}
```

Solicitar redefinição de senha:

```
POST /password/request-reset
```

Body:
```json
{
  "email": "user@example.com"
}
```

Redefinir senha:

```
POST /password/reset
```

Body:
```json
{
  "token": "token_recebido_por_email",
  "new_password": "NovaSenhaSegura123!"
}
```

## 🔐 Segurança e Conformidade

- Hashing de senhas com bcrypt via Passlib.
- Tokens com expiração configurável e armazenamento em blacklist para logout seguro.
- RBAC com verificação granular por função.
- Logs registrados com IP, data/hora e tipo de evento.
- Princípios da LGPD aplicados: minimização, finalidade, segurança e transparência.

## 🧪 Executando Localmente

1. Clone o repositório:
```bash
git clone https://github.com/ViniciusARD/Keylo.git
cd keylo
```

2. Crie um ambiente virtual e instale as dependências:
```bash
python -m venv venv
source venv/bin/activate  # ou venv\Scripts\activate no Windows
pip install -r requirements.txt
```

3. Execute a aplicação:
```bash
uvicorn main:app --reload
```

4. Acesse a documentação interativa:
```
http://127.0.0.1:8000/docs
```