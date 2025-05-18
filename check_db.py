import sqlite3

conn = sqlite3.connect('users.db')
cursor = conn.cursor()
cursor.execute('SELECT username FROM users')
rows = cursor.fetchall()
print("Users in DB:", rows)
conn.close()