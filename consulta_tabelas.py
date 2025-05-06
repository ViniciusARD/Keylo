import sqlite3

# Conectando ao banco de dados SQLite
conn = sqlite3.connect("keylo.db")
cursor = conn.cursor()

# Consultando todos os registros da tabela de logs
cursor.execute("SELECT * FROM refresh_tokens")
logs = cursor.fetchall()

# Exibindo os logs
for log in logs:
    print(log)

# Fechando a conexão
conn.close()
