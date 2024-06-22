import sqlite3
import sys
import os
import re
import time
from PyQt6.QtCore import Qt, QPoint,QSize
from PyQt6.QtWidgets import (QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QTableWidget, 
                             QTableWidgetItem, QLineEdit, QLabel, QMessageBox, QDialog, QComboBox, 
                             QFileDialog, QAbstractItemView,QScrollArea,QInputDialog)
from PyQt6.QtGui import QIcon, QFont,QTextDocument,QTextTableFormat,QTextCursor,QPageLayout,QPixmap
from PyQt6.QtPrintSupport import QPrinter, QPrintDialog
from argon2 import PasswordHasher, Type
import gzip
import csv
import base64
from numpy import place
from icons import *
import openpyxl
from multiprocessing import Pool, cpu_count, Manager
from functools import partial


APPDATA_DIR = os.path.join(os.getenv('LOCALAPPDATA'), 'LogsExplorer')
DB_PATH = os.path.join(APPDATA_DIR, 'mydatabase.db')

if not os.path.exists(APPDATA_DIR):
    os.makedirs(APPDATA_DIR)

ph = PasswordHasher(type=Type.ID)

def create_temp_table(cur, temp_table_name, headers, coltypes):
    columns_def = ', '.join([f"{headers[i]} {coltypes[i]}" for i in range(len(headers))])
    cur.execute(f"CREATE TEMP TABLE {temp_table_name} ({columns_def})")

def move_unique_records(con, temp_table_name, table_name, headers):
    cur = con.cursor()
    columns = ', '.join(headers)
    columns_no_load_id = ', '.join(headers[:-1])
    query = f"""
        INSERT INTO {table_name} ({columns})
        SELECT {columns}
        FROM {temp_table_name}
        WHERE ({columns_no_load_id}) NOT IN (SELECT {columns_no_load_id} FROM {table_name})
    """
    cur.execute(query)
    con.commit()
    cur.close()

def insert_lines(cur, table_name, headers, data_buf):
    placeholders = ','.join(['?'] * len(headers))
    columns = ', '.join(headers)
    query = f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"
    cur.executemany(query, data_buf)

def process_chunk(chunk, table_name, headers, coltypes, load_id):
    data_buf = []
    for cols in chunk:
        while len(cols) < len(coltypes) - 1:
            cols.append("")
        cols.append(load_id)  # добавляем load_id для новой загрузки
        data_buf.append(tuple(cols))
    return data_buf

def import_table_without_duplicates(con, table_fname, table_name=None, header=False, header_comment=False, bufsize=1000):
    con.execute('PRAGMA synchronous = OFF')
    con.execute('PRAGMA journal_mode = OFF')
    con.execute('PRAGMA cache_size = 10000')

    cur = con.cursor()

    if not table_name:
        table_name = auto_table_name(table_fname)

    temp_table_name = f"{table_name}_temp"
    
    print(f"Importing file: {table_fname} => {table_name}")

    with open(table_fname, 'rb') as f:
        if f.read(2) == b'\x1f\x8b':
            f.close()
            f = gzip.open(table_fname, 'rt')
        else:
            f.close()
            f = open(table_fname, 'rt')

    headers = None
    coltypes = None
    buf = []
    data_chunks = []
    inbuf = True
    inheader = (header or header_comment)
    last_line = ""

    start_time = time.time()

    load_id = int(time.time())

    for line in f:
        if line[0] == '#':
            last_line = line
            continue

        if inheader and (header or header_comment):
            if header_comment:
                headers = last_line[1:].strip('\r\n').split('\t')
            else:
                headers = line.strip('\r\n').split('\t')
            inheader = False
            if not header_comment:
                continue

        cols = line.strip('\r\n').split('\t')

        # Remove columns 9, 10, 17, 18, 20 and 27-58
        cols = [col for i, col in enumerate(cols) if i not in [8, 9, 16, 17, 19] + list(range(26, 58))]

        if inbuf:
            buf.append(cols)
            if len(buf) >= bufsize:
                inbuf = False
                coltypes = auto_coltype(buf)
                if headers is None:
                    headers = [f'col_{i+1}' for i in range(len(coltypes))]
                if 'load_id' not in headers:
                    headers.append("load_id")
                    coltypes.append("integer")
                if not table_exists(cur, table_name):
                    create_table(cur, table_name, headers, coltypes)
                create_temp_table(cur, temp_table_name, headers, coltypes)
                data_chunks.append(buf)
                buf = []
        else:
            buf.append(cols)
            if len(buf) >= bufsize:
                data_chunks.append(buf)
                buf = []

    if inbuf and buf:
        coltypes = auto_coltype(buf)
        if headers is None:
            headers = [f'col_{i+1}' for i in range(len(coltypes))]
        if 'load_id' not in headers:
            headers.append("load_id")
            coltypes.append("integer")
        if not table_exists(cur, table_name):
            create_table(cur, table_name, headers, coltypes)
        create_temp_table(cur, temp_table_name, headers, coltypes)
        data_chunks.append(buf)

    pool = Pool(cpu_count())
    process_func = partial(process_chunk, table_name=temp_table_name, headers=headers, coltypes=coltypes, load_id=load_id)
    processed_chunks = pool.map(process_func, data_chunks)
    
    # Flatten the list of processed chunks
    flattened_data = [item for sublist in processed_chunks for item in sublist]

    # Insert the processed data into the temporary table
    insert_lines(cur, temp_table_name, headers, flattened_data)

    # Move unique records from the temporary table to the main table
    move_unique_records(con, temp_table_name, table_name, headers)

    # Drop the temporary table
    cur.execute(f"DROP TABLE {temp_table_name}")
    con.commit()

    pool.close()
    pool.join()

    con.commit()
    cur.close()

    if table_fname != '-':
        f.close()

    end_time = time.time()
    execution_time = end_time - start_time
    print(f"Total execution time for importing '{table_fname}': {execution_time:.2f} seconds")

    num_cores = cpu_count()
    print(f"Number of CPU cores: {num_cores}")

    # Проверка, были ли добавлены новые записи
    cur = con.cursor()
    cur.execute(f"SELECT COUNT(*) FROM {table_name} WHERE load_id = ?", (load_id,))
    new_rows_count = cur.fetchone()[0]

    if new_rows_count > 0:
        # Запись загрузки в историю только если есть новые строки
        cur.execute("INSERT INTO load_history (table_name, file_name, row_count, id) VALUES (?, ?, ?, ?)",
                    (table_name, table_fname, new_rows_count, load_id))
        con.commit()
    cur.close()

def delete_load_history_and_data(load_id, main_window):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute("SELECT table_name FROM load_history WHERE id=?", (load_id,))
    load_info = cur.fetchone()

    if load_info:
        table_name = load_info[0]
        cur.execute(f"DELETE FROM {table_name} WHERE load_id=?", (load_id,))
        cur.execute("DELETE FROM load_history WHERE id=?", (load_id,))
        con.commit()

    cur.close()
    con.close()

    if main_window:
        main_window.reload_data()

def create_history_table(con):
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS load_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            table_name TEXT,
            file_name TEXT,
            load_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            row_count INTEGER
        )
    """)
    con.commit()
    cur.close()

def create_user_table(con):
    cur = con.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            salt BLOB,
            role TEXT,
            approved INTEGER,
            rejected INTEGER
        )
    """)
    con.commit()
    cur.close()

def update_user_table(con):
    cur = con.cursor()
    cur.execute("PRAGMA table_info(users)")
    columns = [col[1] for col in cur.fetchall()]
    if "rejected" not in columns:
        cur.execute("ALTER TABLE users ADD COLUMN rejected INTEGER DEFAULT 0")
    con.commit()
    cur.close()

def register_user(username, password, role, approved, rejected):
    salt = os.urandom(16)
    hash_password = ph.hash(password)
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("INSERT INTO users (username, password, salt, role, approved, rejected) VALUES (?, ?, ?, ?, ?, ?)", 
                    (username, hash_password, salt, role, approved, rejected))
        con.commit()
        return True
    except sqlite3.IntegrityError:
        QMessageBox.warning(None, "Ошибка", "Имя пользователя уже существует.")
        return False
    finally:
        con.close()

def login_user(username, password):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT password, salt, role, approved, rejected FROM users WHERE username=?", (username,))
    user = cur.fetchone()
    con.close()

    if user:
        stored_hash_password, salt, role, approved, rejected = user
        try:
            ph.verify(stored_hash_password, password)
            if approved:
                return True, role
            elif rejected:
                QMessageBox.warning(None, "Ошибка", "Ваша заявка на регистрацию была отклонена.")
            else:
                QMessageBox.warning(None, "Ошибка", "Ваша учетная запись не была одобрена администратором.")
        except Exception as e:
            QMessageBox.warning(None, "Ошибка", "Неверное имя пользователя или пароль.")
    else:
        QMessageBox.warning(None, "Ошибка", "Неверное имя пользователя или пароль.")
    return False, None

def user_exists():
    if not os.path.exists(DB_PATH):
        return False
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE approved = 1")
    user_count = cur.fetchone()[0]
    con.close()
    return user_count > 0

def table_exists(cur, table_name):
    cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
    return cur.fetchone() is not None

def auto_table_name(table_fname):
    table_name = os.path.basename(table_fname)
    table_name = re.sub('.gz$', '', table_name)
    table_name = re.sub('.bgz$', '', table_name)
    table_name = re.sub('.txt$', '', table_name)
    table_name = re.sub('.tsv$', '', table_name)
    return table_name

def auto_coltype(all_cols):
    types = []
    seen = []
    for cols in all_cols:
        while len(types) < len(cols):
            types.append("integer")
            seen.append(False)
        
        for i, col in enumerate(cols):
            if not col:
                continue
            seen[i] = True
            if types[i] == 'integer':
                if col:
                    try:
                        int(col)
                    except:
                        types[i] = 'real'
            if types[i] == 'real':
                if col:
                    try:
                        float(col)
                    except:
                        types[i] = 'text'
    return types

def create_index(cur, table_name, columns):
    index_name = f'idx_{table_name}_{"_".join(columns)}'
    columns_str = ', '.join(columns)
    cur.execute(f'CREATE UNIQUE INDEX IF NOT EXISTS {index_name} ON {table_name} ({columns_str})')

def create_table(cur, name, headers, coltypes):
    if not headers:
        headers = [f'col_{i+1}' for i in range(len(coltypes))]
    
    seen_headers = {}
    for i, colname in enumerate(headers):
        original_colname = colname
        suffix = 1
        while colname in seen_headers:
            colname = f'{original_colname}_{suffix}'
            suffix += 1
        seen_headers[colname] = True
        headers[i] = colname

    if 'load_id' not in headers:
        headers.append("load_id")
        coltypes.append("integer")

    sql = f'CREATE TABLE {name} ('
    for i, coltype in enumerate(coltypes):
        colname = headers[i]
        if i > 0:
            sql += ', '
        sql += f"'{colname}' {coltype}"
    sql += ')'
    print(sql)
    cur.execute(sql)

    create_index(cur, name, headers)

def import_table(con, table_fname, table_name=None, header=False, header_comment=False, bufsize=20):
    cur = con.cursor()

    if not table_name:
        table_name = auto_table_name(table_fname)

    print(f"Importing file: {table_fname} => {table_name}")

    with open(table_fname, 'rb') as f:
        if f.read(2) == b'\x1f\x8b':
            f.close()
            f = gzip.open(table_fname, 'rt')
        else:
            f.close()
            f = open(table_fname, 'rt')

    headers = None
    coltypes = None
    buf = []
    data_buf = []
    inbuf = True
    inheader = (header or header_comment)
    last_line = ""

    for line in f:
        if line[0] == '#':
            last_line = line
            continue

        if inheader and (header or header_comment):
            if header_comment:
                headers = last_line[1:].strip('\r\n').split('\t')
            else:
                headers = line.strip('\r\n').split('\t')
            inheader = False
            if not header_comment:
                continue

        cols = line.strip('\r\n').split('\t')

        # Remove columns 9, 10, 17, 18, 20 and 27-58
        cols = [col for i, col in enumerate(cols) if i not in [8, 9, 16, 17, 19] + list(range(26, 58))]

        if inbuf:
            buf.append(cols)
            if len(buf) >= bufsize:
                inbuf = False
                coltypes = auto_coltype(buf)
                if headers is None:
                    headers = [f'col_{i+1}' for i in range(len(coltypes))]
                if 'load_id' not in headers:
                    headers.append("load_id")
                    coltypes.append("integer")
                create_table(cur, table_name, headers, coltypes)
                for cols in buf:
                    while len(cols) < len(coltypes) - 1:
                        cols.append("")
                    cols.append(1)  # добавляем load_id = 1 для первой загрузки
                    data_buf.append(cols)
                insert_lines(cur, table_name, coltypes, data_buf)
                data_buf.clear()
        else:
            while len(cols) < len(coltypes) - 1:
                cols.append("")
            cols.append(1)  # добавляем load_id = 1 для первой загрузки
            data_buf.append(cols)
            if len(data_buf) >= bufsize:
                insert_lines(cur, table_name, coltypes, data_buf)
                data_buf.clear()

    if inbuf:
        coltypes = auto_coltype(buf)
        if headers is None:
            headers = [f'col_{i+1}' for i in range(len(coltypes))]
        if 'load_id' not in headers:
            headers.append("load_id")
            coltypes.append("integer")
        create_table(cur, table_name, headers, coltypes)
        for cols in buf:
            while len(cols) < len(coltypes) - 1:
                cols.append("")
            cols.append(1)  # добавляем load_id = 1 для первой загрузки
            data_buf.append(cols)

    if data_buf:
        insert_lines(cur, table_name, coltypes, data_buf)

    con.commit()
    cur.close()

    if table_fname != '-':
        f.close()

    # Запись первой загрузки в историю
    cur = con.cursor()
    row_count = sum(1 for row in data_buf)
    cur.execute("INSERT INTO load_history (table_name, file_name, row_count) VALUES (?, ?, ?)", (table_name, table_fname, row_count))
    con.commit()
    cur.close()

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Вход")
        self.setGeometry(0, 0, 200, 100)

        self.layout = QVBoxLayout(self)

        self.username_combo = QComboBox(self)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.login_button = QPushButton("Войти")
        self.register_button = QPushButton("Зарегистрироваться")

        self.layout.addWidget(self.username_combo)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.login_button)
        self.layout.addWidget(self.register_button)

        self.login_button.clicked.connect(self.login)
        self.register_button.clicked.connect(self.register)
        self.password_input.setPlaceholderText("Пароль")
        self.center_window()

        self.load_usernames()

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def load_usernames(self):
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT username FROM users WHERE approved = 1")
        usernames = [row[0] for row in cur.fetchall()]
        con.close()
        self.username_combo.addItems(usernames)

    def login(self):
        username = self.username_combo.currentText()
        password = self.password_input.text()

        success, role = login_user(username, password)
        if success:
            self.accept()

    def register(self):
        register_dialog = RegisterDialog(self)
        register_dialog.exec()

class RegisterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Регистрация")
        self.setGeometry(0, 0, 200, 150)

        self.layout = QVBoxLayout(self)

        self.username_input = QLineEdit(self)
        self.username_input.setPlaceholderText("Имя пользователя")
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_input.setPlaceholderText("Пароль")

        self.role_label = QLabel("Роль:")
        self.role_combo = QComboBox(self)
        self.role_combo.addItems(["admin", "user", "guest"])

        self.register_button = QPushButton("Зарегистрироваться")

        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.role_label)
        self.layout.addWidget(self.role_combo)
        self.layout.addWidget(self.register_button)

        self.register_button.clicked.connect(self.register)

        self.center_window()

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def register(self):
        username = self.username_input.text()
        password = self.password_input.text()
        role = self.role_combo.currentText()

        success = register_user(username, password, role, 0, 0)
        if success:
            QMessageBox.information(self, "Успех", "Заявка на регистрацию отправлена. Ожидайте одобрения администратора.")
            self.accept()

class RegisterAdminDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Регистрация владельца")
        self.setGeometry(0, 0, 200, 100)

        self.layout = QVBoxLayout(self)

        self.username_input = QLineEdit(self)
        self.username_input.setText("owner")
        self.username_input.setReadOnly(True)
        self.password_input = QLineEdit(self)
        self.password_input.setEchoMode(QLineEdit.EchoMode.Password)

        self.register_button = QPushButton("Зарегистрироваться")

        self.layout.addWidget(self.username_input)
        self.layout.addWidget(self.password_input)
        self.layout.addWidget(self.register_button)

        self.register_button.clicked.connect(self.register)
        self.password_input.setPlaceholderText("Пароль")
        self.center_window()

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def register(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not password:
            QMessageBox.warning(self, "Ошибка", "Необходимо ввести пароль.")
            return
        if len(password) < 4:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать как минимум 4 символа.")
            return
        self.accept()
        QMessageBox.information(None, "Регистрация", "Теперь войдите в аккаунт.")

class AdminPanelWindow(QDialog):
    def __init__(self, cursor, conn, parent=None, current_user=None):
        super().__init__(parent)
        self.current_user = current_user
        self.setWindowTitle("Панель администратора")
        self.setGeometry(0, 0, 375, 300)

        self.layout = QVBoxLayout(self)

        self.users_table = QTableWidget()
        self.layout.addWidget(self.users_table)

        self.refresh_button = QPushButton("Обновить таблицу")
        self.refresh_button.clicked.connect(self.load_users)
        self.layout.addWidget(self.refresh_button)

        self.approve_button = QPushButton("Включить пользователя")
        self.approve_button.clicked.connect(self.approve_user)
        self.layout.addWidget(self.approve_button)

        self.reject_button = QPushButton("Отключить пользователя")
        self.reject_button.clicked.connect(self.reject_user)
        self.layout.addWidget(self.reject_button)

        self.delete_user_button = QPushButton("Удалить пользователя")
        self.delete_user_button.clicked.connect(self.delete_user)
        self.layout.addWidget(self.delete_user_button)

        self.change_password_button = QPushButton("Сменить пароль пользователя")
        self.change_password_button.clicked.connect(self.change_password)
        self.layout.addWidget(self.change_password_button)

        self.delete_db_button = QPushButton("Удалить БД", self)
        self.delete_db_button.setStyleSheet("color: red")
        self.delete_db_button.clicked.connect(self.delete_database)
        self.layout.addWidget(self.delete_db_button)

        self.setLayout(self.layout)
        self.load_users()

        self.conn = conn
        self.cursor = cursor

        self.center_window()

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def load_users(self):
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT username, role, approved, rejected FROM users")
        users = cur.fetchall()
        con.close()

        self.users_table.setRowCount(len(users))
        self.users_table.setColumnCount(3)
        self.users_table.setHorizontalHeaderLabels(["Имя пользователя", "Роль", "Статус"])

        for row, user in enumerate(users):
            username, role, approved, rejected = user
            status = "Ожидает" if not approved and not rejected else "Принят" if approved else "Отклонен"
            self.users_table.setItem(row, 0, QTableWidgetItem(username))
            self.users_table.setItem(row, 1, QTableWidgetItem(role))
            self.users_table.setItem(row, 2, QTableWidgetItem(status))

    def approve_user(self):
        selected_row = self.users_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя для одобрения.")
            return
        
        username_item = self.users_table.item(selected_row, 0)
        username = username_item.text()
        if username == self.current_user:
            QMessageBox.warning(self, "Ошибка", "Невозможно включить текущего пользователя.")
            return
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("UPDATE users SET approved = 1, rejected = 0 WHERE username = ?", (username,))
        con.commit()
        con.close()

        QMessageBox.information(self, "Успех", "Пользователь был одобрен.")
        self.load_users()

    def reject_user(self):
        selected_row = self.users_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя для отклонения.")
            return

        username_item = self.users_table.item(selected_row, 0)
        username = username_item.text()
        if username == self.current_user:
            QMessageBox.warning(self, "Ошибка", "Невозможно отключить текущего пользователя.")
            return
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("UPDATE users SET approved = 0, rejected = 1 WHERE username = ?", (username,))
        con.commit()
        con.close()

        QMessageBox.information(self, "Успех", "Пользователь был отклонен.")
        self.load_users()

    def delete_user(self):
        selected_row = self.users_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя для удаления.")
            return

        username_item = self.users_table.item(selected_row, 0)
        role_item = self.users_table.item(selected_row, 1)

        if username_item is None or role_item is None:
            QMessageBox.warning(self, "Ошибка", "Не удалось получить данные пользователя.")
            return

        username = username_item.text()
        user_role = role_item.text()

        if user_role == "owner":
            QMessageBox.warning(self, "Ошибка", "Невозможно удалить владельца БД.")
            return

        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        con.commit()
        con.close()

        QMessageBox.information(self, "Успех", "Пользователь был удален.")
        self.load_users()

        if username == self.current_user:
            QMessageBox.information(self, "Сообщение", "Программа перезапуститься, так как вы удалили себя.")
            self.close_database_connection()
            self.close()
            QApplication.exit()
            os.execl(sys.executable, sys.executable, *sys.argv)

    def close_database_connection(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

    def delete_database(self):
        reply = QMessageBox.question(
            self,
            "Удаление БД",
            "Вы уверены, что хотите удалить базу данных?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            if self.cursor is not None:
                self.cursor.close()
            if self.conn is not None:
                self.conn.close()
            self.conn = None
            self.cursor = None
            try:
                os.remove(DB_PATH)
                QMessageBox.information(self, "Удаление", """БД была успешно удалена.
Программа перезапуститься после закрытия данного окна во избежание ошибок.""")
                self.close_database_connection()
                self.close()
                QApplication.exit()
                os.execl(sys.executable, sys.executable, *sys.argv)
            except FileNotFoundError:
                QMessageBox.warning(self, "Ошибка", "Файл базы данных не найден.")
                
    def change_password(self):
        selected_row = self.users_table.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите пользователя для смены пароля.")
            return

        username_item = self.users_table.item(selected_row, 0)
        username = username_item.text()

        change_password_dialog = ChangePasswordDialog(username, self)
        change_password_dialog.exec()

class MainApplication(QApplication):
    def __init__(self, argv):
        super().__init__(argv)
        self.setStyle("Fusion")
        self.setWindowIcon(QIcon('sql.png'))
        self.window = None
        self.main_window = None

    def run(self):
        if not os.path.exists(DB_PATH):
            if not os.path.exists(APPDATA_DIR):
                os.makedirs(APPDATA_DIR)

            con = sqlite3.connect(DB_PATH)
            create_user_table(con)
            create_history_table(con)  # создание таблицы истории
            con.close()
        else:
            con = sqlite3.connect(DB_PATH)
            update_user_table(con)
            create_history_table(con)  # создание таблицы истории
            con.close()

        while True:
            if user_exists():
                login_dialog = LoginDialog()
                if login_dialog.exec() == QDialog.DialogCode.Accepted:
                    username = login_dialog.username_combo.currentText()
                    success, role = login_user(username, login_dialog.password_input.text())
                    if success:
                        con = sqlite3.connect(DB_PATH)
                        cursor = con.cursor()
                        self.window = EditDatabaseWindow(con, cursor, role, username)
                        self.main_window = self.window  # сохраняем ссылку на главное окно
                        self.window.show()
                        self.exec()
            else:
                QMessageBox.information(None, "Регистрация", "Создайте учетную запись владельца.")
                register_dialog = RegisterAdminDialog()
                if register_dialog.exec() == QDialog.DialogCode.Accepted:
                    con = sqlite3.connect(DB_PATH)
                    cur = con.cursor()
                    try:
                        salt = os.urandom(16)
                        hash_password = ph.hash(register_dialog.password_input.text())
                        cur.execute("INSERT INTO users (username, password, salt, role, approved, rejected) VALUES (?, ?, ?, ?, ?, ?)", 
                                    (register_dialog.username_input.text(), hash_password, salt, 'owner', 1, 0))
                        con.commit()
                    except sqlite3.IntegrityError:
                        QMessageBox.warning(None, "Ошибка", "Имя пользователя уже существует.")
                    finally:
                        con.close()
                    continue
            break

class EditDatabaseWindow(QMainWindow):
    def __init__(self, conn, cursor, user_role, username):
        super().__init__()
        self.setWindowTitle("Редактирование БД")
        self.setGeometry(0, 0, 900, 600)

        self.conn = conn
        self.cursor = cursor
        self.username = username
        self.user_role = user_role

        self.filters = []
        self.filter_inputs = []
        self.help_window = None
        self.admin_panel = None
        self.query_window = None
        self.load_history_dialog = None

        self.central_widget = QWidget(self)
        self.layout = QVBoxLayout(self.central_widget)

        self.table_widget = QTableWidget()
        self.table_widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        self.toolbar = self.addToolBar("")

        # Добавляем иконки и кнопки
        clear_filters_pixmap = QPixmap()
        clear_filters_pixmap.loadFromData(base64.b64decode(clear_filters_icon))
        clear_filters_icon_obj = QIcon(clear_filters_pixmap)

        clear_sorting_pixmap = QPixmap()
        clear_sorting_pixmap.loadFromData(base64.b64decode(clear_sorting_icon))
        clear_sorting_icon_obj = QIcon(clear_sorting_pixmap)

        add_data_pixmap = QPixmap()
        add_data_pixmap.loadFromData(base64.b64decode(add_data_icon))
        add_data_icon_obj = QIcon(add_data_pixmap)

        help_pixmap = QPixmap()
        help_pixmap.loadFromData(base64.b64decode(help_icon))
        help_icon_obj = QIcon(help_pixmap)

        logout_pixmap = QPixmap()
        logout_pixmap.loadFromData(base64.b64decode(logout_icon))
        logout_icon_obj = QIcon(logout_pixmap)

        export_csv_pixmap = QPixmap()
        export_csv_pixmap.loadFromData(base64.b64decode(export_csv_icon))
        export_csv_icon_obj = QIcon(export_csv_pixmap)

        print_pixmap = QPixmap()
        print_pixmap.loadFromData(base64.b64decode(print_icon))
        print_icon_obj = QIcon(print_pixmap)

        admin_panel_button_pixmap = QPixmap()
        admin_panel_button_pixmap.loadFromData(base64.b64decode(admin_panel_button))
        admin_panel_button_obj = QIcon(admin_panel_button_pixmap)

        query_pixmap = QPixmap()
        query_pixmap.loadFromData(base64.b64decode(query_icon))  
        query_icon_obj = QIcon(query_pixmap)

        self.clear_filters_button = QPushButton()
        self.clear_filters_button.setIcon(clear_filters_icon_obj)
        self.clear_filters_button.setToolTip("Очистить все фильтры")
        self.clear_filters_button.clicked.connect(self.clear_filters)

        self.clear_sorting_button = QPushButton()
        self.clear_sorting_button.setIcon(clear_sorting_icon_obj)
        self.clear_sorting_button.setToolTip("Очистить сортировку")
        self.clear_sorting_button.clicked.connect(self.clear_sorting)

        self.add_button = QPushButton()
        self.add_button.setIcon(add_data_icon_obj)
        self.add_button.setToolTip("Догрузить данные")
        self.add_button.clicked.connect(self.load_more_data)

        self.help_button = QPushButton()
        self.help_button.setIcon(help_icon_obj)
        self.help_button.setToolTip("Справка")
        self.help_button.clicked.connect(self.open_help)

        self.logout_button = QPushButton()
        self.logout_button.setIcon(logout_icon_obj)
        self.logout_button.setToolTip("Выйти из аккаунта")
        self.logout_button.clicked.connect(self.logout)

        self.export_csv_button = QPushButton()
        self.export_csv_button.setIcon(export_csv_icon_obj)
        self.export_csv_button.setToolTip("Экспорт в CSV")
        self.export_csv_button.clicked.connect(self.export_to_csv)

        self.print_button = QPushButton()
        self.print_button.setIcon(print_icon_obj)
        self.print_button.setToolTip("Печать")
        self.print_button.clicked.connect(self.print_table)

        self.toolbar.addWidget(self.clear_filters_button)
        self.toolbar.addWidget(self.clear_sorting_button)
        self.toolbar.addWidget(self.add_button)
        self.toolbar.addWidget(self.help_button)
        self.toolbar.addWidget(self.logout_button)
        self.toolbar.addWidget(self.export_csv_button)
        self.toolbar.addWidget(self.print_button)

        if self.user_role == "admin" or self.user_role == "owner":
            self.admin_panel_button = QPushButton()
            self.admin_panel_button.setIcon(admin_panel_button_obj)
            self.admin_panel_button.setToolTip("Панель админа")
            self.admin_panel_button.clicked.connect(self.open_admin_panel)
            self.toolbar.addWidget(self.admin_panel_button)

        self.query_button = QPushButton()
        self.query_button.setIcon(query_icon_obj)
        self.query_button.setToolTip("Окно запросов")
        self.query_button.clicked.connect(self.open_query_window)
        self.toolbar.addWidget(self.query_button)

        self.layout.addWidget(self.table_widget)
        self.setCentralWidget(self.central_widget)

        self.page_size = 100  # Количество строк для загрузки за раз
        self.current_page = 0
        self.total_rows = 0
        self.sort_columns = []

        self.sort_input_row = 0  # Перемещено сюда

        self.table_widget.verticalScrollBar().valueChanged.connect(self.on_scroll)
        self.table_widget.horizontalHeader().sectionClicked.connect(self.on_section_clicked)

        self.check_and_load_table()
        self.setup_table_with_filters()
        self.center_window()

        self.clear_filters_button.setFixedSize(48, 48)
        self.clear_filters_button.setIconSize(QSize(24, 24))

        self.clear_sorting_button.setFixedSize(48, 48)
        self.clear_sorting_button.setIconSize(QSize(24, 24))

        self.add_button.setFixedSize(48, 48)
        self.add_button.setIconSize(QSize(24, 24))

        self.help_button.setFixedSize(48, 48)
        self.help_button.setIconSize(QSize(24, 24))

        self.logout_button.setFixedSize(48, 48)
        self.logout_button.setIconSize(QSize(24, 24))

        self.export_csv_button.setFixedSize(48, 48)
        self.export_csv_button.setIconSize(QSize(24, 24))

        self.print_button.setFixedSize(48, 48)
        self.print_button.setIconSize(QSize(24, 24))

        if self.user_role == "admin" or self.user_role == "owner":
            self.admin_panel_button.setFixedSize(48, 48)
            self.admin_panel_button.setIconSize(QSize(24, 24))

        self.query_button.setFixedSize(48, 48)
        self.query_button.setIconSize(QSize(24, 24))

        self.load_history_button = QPushButton("История дозагрузок")
        self.load_history_button.clicked.connect(self.open_load_history)
        self.toolbar.addWidget(self.load_history_button)


    def reload_data(self):
        self.current_page = 0
        self.table_widget.setRowCount(0)  # Очищаем все строки
        self.setup_table_with_filters()
        self.load_data()

    def setup_table_with_filters(self):
        table_name = "log_table"
        query = f"PRAGMA table_info({table_name})"
        self.cursor.execute(query)
        headers = [description[1] for description in self.cursor.fetchall()]

        self.filters = headers

        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

        self.filter_inputs = []

        self.table_widget.insertRow(0)  # Вставляем строку для фильтров

        for i, header in enumerate(headers):
            filter_input = QLineEdit(self.table_widget)
            filter_input.setPlaceholderText(f"Фильтр по {header}")
            filter_input.textChanged.connect(self.apply_filters)
            self.filter_inputs.append(filter_input)
            self.table_widget.setCellWidget(0, i, filter_input)

    def apply_filters(self):
        self.current_page = 0
        self.table_widget.setRowCount(1)  # Очищаем все строки данных, кроме строки с фильтрами
        self.load_data()

    def load_data(self):
        table_name = "log_table"
        try:
            query = f"SELECT COUNT(*) FROM {table_name}"
            filter_query = self.build_filter_query()
            if filter_query:
                query += f" WHERE {filter_query}"
            self.cursor.execute(query)
            self.total_rows = self.cursor.fetchone()[0]

            headers_query = f"PRAGMA table_info({table_name})"
            self.cursor.execute(headers_query)
            headers = [description[1] for description in self.cursor.fetchall()]

            self.table_widget.setColumnCount(len(headers))
            self.table_widget.setHorizontalHeaderLabels(headers)

            self.load_page()
            self.update_sort_indicator()

            # Установить максимальное значение для скроллбара
            self.table_widget.verticalScrollBar().setMaximum(self.total_rows)

            # Обновить историю дозагрузок
            self.update_load_history()

        except sqlite3.OperationalError as e:
            QMessageBox.warning(None, "Ошибка", f"Таблица 'log_table' не найдена в базе данных. Ошибка: {e}")

    def update_sort_indicator(self):
        for i in range(self.table_widget.columnCount()):
            column_name = self.table_widget.horizontalHeaderItem(i).text().replace(" ↑", "").replace(" ↓", "")
            for col, order in self.sort_columns:
                if col == column_name:
                    column_name += " ↑" if order == Qt.SortOrder.AscendingOrder else " ↓"
            self.table_widget.horizontalHeaderItem(i).setText(column_name)

    def update_load_history(self):
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT id, table_name, file_name, load_time, row_count FROM load_history")
        history = cur.fetchall()
        con.close()

        # Обновление истории в пользовательском интерфейсе
        if self.load_history_dialog:
            self.load_history_dialog.table_widget.setRowCount(len(history))
            self.load_history_dialog.table_widget.setColumnCount(5)
            self.load_history_dialog.table_widget.setHorizontalHeaderLabels(["ID", "Таблица", "Файл", "Дата загрузки", "Количество строк"])

            for row, load in enumerate(history):
                for col, data in enumerate(load):
                    self.load_history_dialog.table_widget.setItem(row, col, QTableWidgetItem(str(data)))

    def build_filter_query(self):
        filters = []
        for header, filter_input in zip(self.filters, self.filter_inputs):
            filter_text = filter_input.text().strip()
            if filter_text:
                filters.append(f"{header} LIKE '%{filter_text}%'")
        return " AND ".join(filters)

    def open_load_history(self):
        self.load_history_dialog = LoadHistoryDialog(self)
        self.load_history_dialog.exec()

    def open_query_window(self):
        if not self.query_window:
            self.query_window = QueryWindow(self.conn, self.cursor)
            self.query_window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.query_window.destroyed.connect(self.on_query_window_closed)
            self.query_window.show()
        else:
            self.query_window.raise_()
            self.query_window.activateWindow()

    def on_query_window_closed(self):
        self.query_window = None

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def export_to_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            try:
                with open(file_name, 'w', newline='', encoding='utf-8') as file:
                    writer = csv.writer(file)
                    headers = [self.table_widget.horizontalHeaderItem(i).text() for i in range(self.table_widget.columnCount())]
                    writer.writerow(headers)

                    self.cursor.execute("SELECT * FROM log_table")
                    all_rows = self.cursor.fetchall()
                    for row in all_rows:
                        writer.writerow(row)

                QMessageBox.information(self, "Успех", "Данные успешно экспортированы в CSV.")
            except Exception as e:
                QMessageBox.critical(self, "Ошибка", f"Произошла ошибка при экспорте данных: {e}")

    def print_table(self):
        column_count = self.table_widget.columnCount()
        row_count = self.table_widget.rowCount()

        if column_count == 0 or row_count == 0:
            QMessageBox.warning(self, "Ошибка", "Нет данных для печати.")
            return

        printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        printer.setPageOrientation(QPageLayout.Orientation.Landscape)  # Установка альбомной ориентации

        print_dialog = QPrintDialog(printer, self)
        if print_dialog.exec() == QDialog.DialogCode.Accepted:
            self.print_data(printer)

    def print_data(self, printer):
        document = QTextDocument()
        cursor = QTextCursor(document)

        table_format = QTextTableFormat()
        table_format.setBorder(1)
        table_format.setCellPadding(4)
        table_format.setCellSpacing(0)

        table = cursor.insertTable(self.table_widget.rowCount() + 1, self.table_widget.columnCount(), table_format)

        # Вставка заголовков таблицы
        for column in range(self.table_widget.columnCount()):
            header_item = self.table_widget.horizontalHeaderItem(column)
            if header_item is not None:
                cursor.insertText(header_item.text())
            cursor.movePosition(QTextCursor.MoveOperation.NextCell)

        # Вставка данных таблицы
        for row in range(self.table_widget.rowCount()):
            for column in range(self.table_widget.columnCount()):
                item = self.table_widget.item(row, column)
                if item is not None:
                    cursor.insertText(item.text())
                cursor.movePosition(QTextCursor.MoveOperation.NextCell)

        document.print(printer)

    def open_help(self):
        if not self.help_window:
            self.help_window = HelpWindow(self)
            self.help_window.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.help_window.destroyed.connect(self.on_help_window_closed)
            self.help_window.show()
        else:
            self.help_window.raise_()
            self.help_window.activateWindow()

    def on_help_window_closed(self):
        self.help_window = None

    def open_admin_panel(self):
        if not self.admin_panel:
            self.admin_panel = AdminPanelWindow(self.cursor, self.conn, self, self.username)
            self.admin_panel.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
            self.admin_panel.destroyed.connect(self.on_admin_panel_closed)
            self.admin_panel.show()
        else:
            self.admin_panel.raise_()
            self.admin_panel.activateWindow()

    def on_admin_panel_closed(self):
        self.admin_panel = None

    def on_scroll(self, value):
        scrollbar = self.table_widget.verticalScrollBar()
        if value == scrollbar.maximum():
            self.current_page += 1
            self.load_page()

    def load_page(self):
        start_row = self.current_page * self.page_size
        table_name = "log_table"
        query = f"SELECT * FROM {table_name}"
        filter_query = self.build_filter_query()
        if filter_query:
            query += f" WHERE {filter_query}"
        if self.sort_columns:
            sort_query = ", ".join([f"{col} {'ASC' if order == Qt.SortOrder.AscendingOrder else 'DESC'}" for col, order in self.sort_columns])
            query += f" ORDER BY {sort_query}"
        query += f" LIMIT {self.page_size} OFFSET {start_row}"
        self.cursor.execute(query)
        result = self.cursor.fetchall()

        current_row_count = self.table_widget.rowCount()
        self.table_widget.setRowCount(current_row_count + len(result))

        for i, row in enumerate(result):
            for j, item in enumerate(row):
                table_item = QTableWidgetItem(str(item))
                self.table_widget.setItem(current_row_count + i, j, table_item)

        # Установить текущее значение скроллбара, чтобы он не скакал вверх
            self.table_widget.verticalScrollBar().setValue(start_row)
            
        filters = []
        for header, filter_input in zip(self.filters, self.filter_inputs):
            filter_text = filter_input.text().strip()
            if filter_text:
                filters.append(f"{header} LIKE '%{filter_text}%'")
        return " AND ".join(filters)
        table_name = "log_table"
        try:
            query = f"SELECT COUNT(*) FROM {table_name}"
            filter_query = self.build_filter_query()
            if filter_query:
                query += f" WHERE {filter_query}"
            self.cursor.execute(query)
            self.total_rows = self.cursor.fetchone()[0]

            headers_query = f"PRAGMA table_info({table_name})"
            self.cursor.execute(headers_query)
            headers = [description[1] for description in self.cursor.fetchall()]

            self.table_widget.setColumnCount(len(headers))
            self.table_widget.setHorizontalHeaderLabels(headers)

            self.update_sort_indicator()
            self.load_page()

            # Установить максимальное значение для скроллбара
            self.table_widget.verticalScrollBar().setMaximum(self.total_rows)

        except sqlite3.OperationalError as e:
            QMessageBox.warning(None, "Ошибка", f"Таблица 'log_table' не найдена в базе данных. Ошибка: {e}")

    def clear_filters(self):
        for filter_input in self.filter_inputs:
            filter_input.clear()
        self.current_page = 0
        self.table_widget.setRowCount(1)
        for i, filter_input in enumerate(self.filter_inputs):
            self.table_widget.setCellWidget(self.sort_input_row, i, filter_input)
        self.load_data()

    def clear_sorting(self):
        self.sort_columns = []
        self.current_page = 0
        self.table_widget.setRowCount(1)
        for i, filter_input in enumerate(self.filter_inputs):
            self.table_widget.setCellWidget(self.sort_input_row, i, filter_input)
        self.load_data()

        table_name = "log_table"
        query = f"PRAGMA table_info({table_name})"
        self.cursor.execute(query)
        headers = [description[1] for description in self.cursor.fetchall()]

        self.filters = headers

        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

        self.filter_inputs = []

        self.table_widget.insertRow(0)  # Вставляем строку для фильтров

        for i, header in enumerate(headers):
            filter_input = QLineEdit(self.table_widget)
            filter_input.setPlaceholderText(f"Фильтр по {header}")
            filter_input.textChanged.connect(self.apply_filters)
            self.filter_inputs.append(filter_input)
            self.table_widget.setCellWidget(0, i, filter_input)

    def check_and_load_table(self):
        try:
            if not table_exists(self.cursor, 'log_table'):
                QMessageBox.information(None, "Отсутствие логов", "Таблица с логами не найдена. Выберите .log файл для загрузки.")
                self.center_window()
                file_name, _ = self.show_centered_file_dialog()
                if file_name:
                    import_table(self.conn, file_name, 'log_table')
                    QMessageBox.information(None, "Успех", "Лог-файл успешно импортирован в базу данных.")
                    self.load_data()
            else:
                self.load_data()
        except sqlite3.Error as e:
            self.center_window()
            QMessageBox.critical(None, "Ошибка", f"Ошибка при работе с базой данных: {e}")

    def show_centered_message(self, icon, title, text):
        message_box = QMessageBox(self)
        message_box.setIcon(icon)
        message_box.setWindowTitle(title)
        message_box.setText(text)
        self.center_window()
        message_box.exec()

    def show_centered_file_dialog(self):
        file_dialog = QFileDialog(self)
        file_dialog.setFileMode(QFileDialog.FileMode.ExistingFile)
        file_dialog.setNameFilters(["Log Files (*.log)", "All Files (*)"])
        self.center_window()
        if file_dialog.exec():
            return file_dialog.selectedFiles()[0], file_dialog.selectedNameFilter()
        return None, None

    def on_section_clicked(self, logicalIndex):
        header = self.table_widget.horizontalHeader()
        column_name = self.table_widget.horizontalHeaderItem(logicalIndex).text().replace(" ↑", "").replace(" ↓", "")
        sort_order = header.sortIndicatorOrder()

        found = False
        for i, (col, order) in enumerate(self.sort_columns):
            if col == column_name:
                if order == Qt.SortOrder.AscendingOrder:
                    self.sort_columns[i] = (col, Qt.SortOrder.DescendingOrder)
                else:
                    del self.sort_columns[i]
                found = True
                break

        if not found:
            self.sort_columns.append((column_name, Qt.SortOrder.AscendingOrder))

        self.update_sort_indicator()
        self.current_page = 0
        self.table_widget.setRowCount(1)
        for i, filter_input in enumerate(self.filter_inputs):
            self.table_widget.setCellWidget(self.sort_input_row, i, filter_input)
        self.load_data()

    def close_database_connection(self):
        if self.conn:
            self.conn.close()
            self.conn = None
            self.cursor = None

    def logout(self):
        reply = QMessageBox.question(self, "Выход", "Вы уверены, что хотите выйти из аккаунта?",
                                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.close_database_connection()
            self.close()
            QApplication.exit()
            os.execl(sys.executable, sys.executable, *sys.argv)

    def load_more_data(self):
        file_name, _ = QFileDialog.getOpenFileName(self, "Выберите лог-файл", "", "Log Files (*.log);;All Files (*)")
        if file_name:
            con = sqlite3.connect(DB_PATH)
            import_table_without_duplicates(con, file_name, 'log_table')
            self.reload_data()
            con.close()

class HelpWindow(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Руководство пользователя")
        self.resize(400, 300)

        self.layout = QVBoxLayout(self)
        self.pages = [
            "Руководство по использованию программы:\n"
            "Работа с базой данных:\n"
            "- Кнопка 'Открыть БД' позволяет выбрать лог-файл, который будет импортирован в базу данных.\n"
            "- Если база данных уже существует, кнопка 'Открыть БД' открывает окно для редактирования данных базы данных.\n"
            "- Кнопка 'Справка' показывает это руководство пользователя.\n"
            "- Кнопка 'Удалить БД' позволяет удалить текущую базу данных."
        ]

        self.current_page = 0

        self.text_label = QLabel()
        self.text_label.setWordWrap(True)
        self.text_label.setFont(QFont("Arial", 13))
        self.next_button = QPushButton("Далее")
        self.prev_button = QPushButton("Назад")
        self.close_button = QPushButton("Закрыть")

        self.next_button.clicked.connect(self.next_page)
        self.prev_button.clicked.connect(self.prev_page)
        self.close_button.clicked.connect(self.close)

        self.update_page()

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.prev_button)
        button_layout.addWidget(self.next_button)
        button_layout.addWidget(self.close_button)

        self.layout.addWidget(self.text_label)
        self.layout.addLayout(button_layout)

        self.setLayout(self.layout)

    def update_page(self):
        text = self.pages[self.current_page]
        self.text_label.setText(text)

        self.prev_button.setEnabled(self.current_page > 0)
        self.next_button.setEnabled(self.current_page < len(self.pages) - 1)

    def next_page(self):
        if self.current_page < len(self.pages) - 1:
            self.current_page += 1
            self.update_page()

    def prev_page(self):
        if self.current_page > 0:
            self.current_page -= 1
            self.update_page()

class ChangePasswordDialog(QDialog):
    def __init__(self, username, parent=None):
        super().__init__(parent)
        self.username = username
        self.setWindowTitle("Смена пароля")
        self.setGeometry(0, 0, 200, 150)

        self.layout = QVBoxLayout(self)

        self.new_password_input = QLineEdit(self)
        self.new_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.new_password_input.setPlaceholderText("Новый пароль")

        self.confirm_password_input = QLineEdit(self)
        self.confirm_password_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_input.setPlaceholderText("Подтвердите пароль")

        self.change_button = QPushButton("Изменить пароль")

        self.layout.addWidget(self.new_password_input)
        self.layout.addWidget(self.confirm_password_input)
        self.layout.addWidget(self.change_button)

        self.change_button.clicked.connect(self.change_password)

        self.center_window()

    def center_window(self):
        screen_geometry = QApplication.primaryScreen().availableGeometry()
        center_x = screen_geometry.width() // 2
        center_y = screen_geometry.height() // 2 - 50
        window_geometry = self.frameGeometry()
        window_geometry.moveCenter(QPoint(center_x, center_y))
        self.move(window_geometry.topLeft())

    def change_password(self):
        new_password = self.new_password_input.text()
        confirm_password = self.confirm_password_input.text()

        if new_password != confirm_password:
            QMessageBox.warning(self, "Ошибка", "Пароли не совпадают.")
            return

        if len(new_password) < 4:
            QMessageBox.warning(self, "Ошибка", "Пароль должен содержать как минимум 4 символа.")
            return

        hash_password = ph.hash(new_password)
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("UPDATE users SET password = ? WHERE username = ?", (hash_password, self.username))
        con.commit()
        con.close()

        QMessageBox.information(self, "Успех", "Пароль успешно изменен.")
        self.accept()

class QueryWindow(QMainWindow):
    def __init__(self, conn, cursor):
        super().__init__()

        self.conn = conn
        self.cursor = cursor
        self.setWindowTitle("Окно запросов")
        self.setGeometry(0, 0, 800, 600)

        self.page_size = 1000  # Размер страницы данных для подгрузки
        self.current_page = 0

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)
        form_layout = QVBoxLayout()

        self.filter_widgets = []

        self.add_filter_button = QPushButton("Добавить фильтр")
        self.add_filter_button.clicked.connect(self.add_filter)

        form_layout.addWidget(self.add_filter_button)

        self.filter_area = QWidget()
        self.filter_area.setLayout(form_layout)

        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setWidget(self.filter_area)

        layout.addWidget(self.scroll_area)

        self.table_widget = QTableWidget()
        self.table_widget.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table_widget.verticalScrollBar().valueChanged.connect(self.on_scroll)
        layout.addWidget(self.table_widget)

        self.export_csv_button = QPushButton("Экспорт в CSV")
        self.export_csv_button.clicked.connect(self.export_to_csv)
        layout.addWidget(self.export_csv_button)

        self.export_excel_button = QPushButton("Экспорт в Excel")
        self.export_excel_button.clicked.connect(self.export_to_excel)
        layout.addWidget(self.export_excel_button)

        self.load_data()

    def add_filter(self):
        filter_widget = QWidget()
        filter_layout = QHBoxLayout(filter_widget)

        column_combo = QComboBox()
        self.cursor.execute("PRAGMA table_info(log_table)")
        columns = [description[1] for description in self.cursor.fetchall()]
        column_combo.addItems(columns)

        condition_combo = QComboBox()
        condition_combo.setObjectName("conditionComboBox")  # Задаем имя объекту
        condition_combo.addItems(["=", ">", "<", ">=", "<=", "LIKE"])

        value_edit = QLineEdit()

        remove_button = QPushButton("Удалить")
        remove_button.clicked.connect(lambda: self.remove_filter(filter_widget))

        filter_layout.addWidget(column_combo)
        filter_layout.addWidget(condition_combo)
        filter_layout.addWidget(value_edit)
        filter_layout.addWidget(remove_button)

        self.filter_widgets.append(filter_widget)
        self.filter_area.layout().addWidget(filter_widget)

        # Добавляем обработчик событий для обновления данных при изменении фильтра
        column_combo.currentIndexChanged.connect(self.load_data)
        condition_combo.currentIndexChanged.connect(self.load_data)
        value_edit.textChanged.connect(self.load_data)

    def remove_filter(self, filter_widget):
        self.filter_widgets.remove(filter_widget)
        self.filter_area.layout().removeWidget(filter_widget)
        filter_widget.deleteLater()
        self.load_data()

    def load_data(self):
        self.table_widget.setRowCount(0)
        self.current_page = 0
        self.setup_table_headers()  # Установим заголовки таблицы
        self.load_page()

    def setup_table_headers(self):
        self.cursor.execute("PRAGMA table_info(log_table)")
        headers = [description[1] for description in self.cursor.fetchall()]
        self.table_widget.setColumnCount(len(headers))
        self.table_widget.setHorizontalHeaderLabels(headers)

    def load_page(self):
        start_row = self.current_page * self.page_size + 1  # Изменено значение start_row

        table_name = "log_table"
        query = f"SELECT * FROM {table_name}"
        filter_query = self.build_filter_query()
        if filter_query:
            query += f" WHERE {filter_query}"
        if self.sort_columns:
            sort_query = ", ".join([f"{col} {'ASC' if order == Qt.SortOrder.AscendingOrder else 'DESC'}" for col, order in self.sort_columns])
            query += f" ORDER BY {sort_query}"
        query += f" LIMIT {self.page_size} OFFSET {start_row - 1}"  # Изменено значение start_row - 1
        self.cursor.execute(query)
        result = self.cursor.fetchall()

        current_row_count = self.table_widget.rowCount()
        self.table_widget.setRowCount(current_row_count + len(result))

        for i, row in enumerate(result):
            for j, item in enumerate(row):
                table_item = QTableWidgetItem(str(item))
                self.table_widget.setItem(current_row_count + i, j, table_item)

        # Установить текущее значение скроллбара, чтобы он не скакал вверх
        self.table_widget.verticalScrollBar().setValue(start_row - 1)  # Изменено значение start_row - 1

    def on_scroll(self, value):
        scrollbar = self.table_widget.verticalScrollBar()
        if value == scrollbar.maximum():
            self.load_page()

    def export_to_csv(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "CSV Files (*.csv);;All Files (*)")
        if file_name:
            query = "SELECT * FROM log_table"
            filters = []

            for widget in self.filter_widgets:
                column = widget.findChild(QComboBox).currentText()
                condition = widget.findChild(QComboBox).currentText()
                value = widget.findChild(QLineEdit).text()

                if value:
                    filters.append(f"{column} {condition} ?")
            
            query_params = [widget.findChild(QLineEdit).text() for widget in self.filter_widgets if widget.findChild(QLineEdit).text()]

            if filters:
                query += " WHERE " + " AND ".join(filters)

            self.cursor.execute(query, query_params)
            rows = self.cursor.fetchall()

            with open(file_name, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                headers = [self.table_widget.horizontalHeaderItem(i).text() for i in range(self.table_widget.columnCount())]
                writer.writerow(headers)
                writer.writerows(rows)

    def export_to_excel(self):
        file_name, _ = QFileDialog.getSaveFileName(self, "Сохранить файл", "", "Excel Files (*.xlsx);;All Files (*)")
        if file_name:
            query = "SELECT * FROM log_table"
            filters = []

            for widget in self.filter_widgets:
                column = widget.findChild(QComboBox).currentText()
                condition = widget.findChild(QComboBox).currentText()
                value = widget.findChild(QLineEdit).text()

                if value:
                    filters.append(f"{column} {condition} ?")
            
            query_params = [widget.findChild(QLineEdit).text() for widget in self.filter_widgets if widget.findChild(QLineEdit).text()]

            if filters:
                query += " WHERE " + " AND ".join(filters)

            self.cursor.execute(query, query_params)
            rows = self.cursor.fetchall()

            workbook = openpyxl.Workbook()
            sheet = workbook.active

            headers = [self.table_widget.horizontalHeaderItem(i).text() for i in range(self.table_widget.columnCount())]
            sheet.append(headers)
            for row in rows:
                sheet.append(row)

            workbook.save(file_name)

class LoadHistoryDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("История дозагрузок")
        self.setGeometry(0, 0, 600, 400)

        self.layout = QVBoxLayout(self)

        self.table_widget = QTableWidget()
        self.table_widget.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.layout.addWidget(self.table_widget)

        self.delete_button = QPushButton("Удалить выбранную дозагрузку")
        self.delete_button.clicked.connect(self.delete_selected_load)
        self.layout.addWidget(self.delete_button)

        self.load_history()

    def load_history(self):
        con = sqlite3.connect(DB_PATH)
        cur = con.cursor()
        cur.execute("SELECT id, table_name, file_name, load_time, row_count FROM load_history")
        history = cur.fetchall()
        con.close()

        self.table_widget.setRowCount(len(history))
        self.table_widget.setColumnCount(5)
        self.table_widget.setHorizontalHeaderLabels(["ID", "Таблица", "Файл", "Дата загрузки", "Количество строк"])

        for row, load in enumerate(history):
            for col, data in enumerate(load):
                self.table_widget.setItem(row, col, QTableWidgetItem(str(data)))

    def delete_selected_load(self):
        selected_row = self.table_widget.currentRow()
        if selected_row == -1:
            QMessageBox.warning(self, "Ошибка", "Выберите дозагрузку для удаления.")
            return

        load_id = int(self.table_widget.item(selected_row, 0).text())

        reply = QMessageBox.question(
            self,
            "Удаление дозагрузки",
            f"Вы уверены, что хотите удалить дозагрузку с ID {load_id}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            main_window = QApplication.instance().main_window
            delete_load_history_and_data(load_id, main_window)
            self.load_history()
            QMessageBox.information(self, "Успех", f"Дозагрузка с ID {load_id} была удалена.")

if __name__ == '__main__':
    app = MainApplication(sys.argv)
    app.run()
