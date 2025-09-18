import sqlite3
user = input('id: ')
q = 'SELECT * FROM users WHERE id = ' + user
conn = sqlite3.connect(':memory:')
conn.execute(q)
