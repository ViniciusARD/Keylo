import sqlite3

# Conectando ao banco de dados SQLite
conn = sqlite3.connect("keylo.db")
cursor = conn.cursor()

# Defina o email do usuário que você quer tornar admin
email_alvo = "vini@example.com"

# Verifica se o usuário existe
cursor.execute("SELECT id, papel FROM usuarios WHERE email = ?", (email_alvo,))
usuario = cursor.fetchone()

if usuario:
    usuario_id, papel_atual = usuario

    if papel_atual == "admin":
        print(f"O usuário '{email_alvo}' já é admin.")
    else:
        # Atualiza o campo 'papel' para 'admin'
        cursor.execute("""
            UPDATE usuarios
            SET papel = 'admin'
            WHERE id = ?
        """, (usuario_id,))
        conn.commit()
        print(f"Usuário '{email_alvo}' promovido a admin.")
else:
    print(f"Usuário com email '{email_alvo}' não encontrado.")

# Fechando a conexão
conn.close()
