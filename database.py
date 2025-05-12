from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# URL do banco de dados SQLite
DATABASE_URL = "sqlite:///./keylo.db"

# Cria o motor de conexão com SQLite
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# Cria a sessão para interações com o banco
SessionLocal = sessionmaker(bind=engine, autocommit=False, autoflush=False)

# Classe base para os modelos
Base = declarative_base()
