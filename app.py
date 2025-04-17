
import tkinter as tk
from tkinter import ttk, messagebox
import mysql.connector
import hashlib
from cryptography.fernet import Fernet
import os

# Database configuration
DB_CONFIG = {
    'host': '',
    'user': '',
    'password': '',
    'database': ''
}

# Encryption key handling
def load_or_create_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
    else:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
    return Fernet(key)

fernet = load_or_create_key()

class CreditCardVault:
    def __init__(self, root):
        self.root = root
        self.root.title("Credit Card Vault")
        self.root.geometry("800x600")
        self.current_user = None
        self.current_role = None
        self.init_gui()
        self.init_db()

    def init_gui(self):
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        self.login_tab = ttk.Frame(self.tabs)
        self.card_tab = ttk.Frame(self.tabs)
        self.admin_tab = ttk.Frame(self.tabs)

        self.tabs.add(self.login_tab, text="Login")
        self.tabs.add(self.card_tab, text="My Cards")
        self.tabs.add(self.admin_tab, text="Admin Panel")

        self.setup_login()
        self.setup_card()
        self.setup_admin()

    def setup_login(self):
        ttk.Label(self.login_tab, text="Username:").grid(row=0, column=0, padx=10, pady=5)
        self.username_entry = ttk.Entry(self.login_tab)
        self.username_entry.grid(row=0, column=1)

        ttk.Label(self.login_tab, text="Password:").grid(row=1, column=0, padx=10, pady=5)
        self.password_entry = ttk.Entry(self.login_tab, show="*")
        self.password_entry.grid(row=1, column=1)

        ttk.Button(self.login_tab, text="Login", command=self.login).grid(row=2, column=1, pady=10)

    def setup_card(self):
        fields = ["Cardholder Name", "Card Number", "Expiration Date", "CVV"]
        self.card_entries = {}

        for i, field in enumerate(fields):
            ttk.Label(self.card_tab, text=field + ":").grid(row=i, column=0, padx=10, pady=5)
            entry = ttk.Entry(self.card_tab, show="*" if field == "CVV" else "")
            entry.grid(row=i, column=1)
            self.card_entries[field] = entry

        ttk.Button(self.card_tab, text="Add Card", command=self.add_card).grid(row=4, column=1, pady=5)
        ttk.Button(self.card_tab, text="View My Cards", command=self.view_cards).grid(row=5, column=1)

    def setup_admin(self):
        ttk.Label(self.admin_tab, text="Admin Panel").grid(row=0, column=0, padx=10, pady=10)
        ttk.Button(self.admin_tab, text="View Users", command=self.view_all_users).grid(row=1, column=0, pady=5)
        ttk.Button(self.admin_tab, text="View All Cards", command=self.view_all_cards).grid(row=2, column=0, pady=5)

    def init_db(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS Users (
                user_id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(50) UNIQUE,
                password_hash VARCHAR(64),
                role ENUM('admin', 'merchant', 'customer')
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS CreditCards (
                card_id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT,
                cardholder_name VARCHAR(100),
                card_number TEXT,
                expiration_date VARCHAR(20),
                cvv TEXT,
                FOREIGN KEY (user_id) REFERENCES Users(user_id)
            )
        """)

        admin_password = hashlib.sha256("admin123".encode()).hexdigest()
        cursor.execute("INSERT IGNORE INTO Users (username, password_hash, role) VALUES (%s, %s, %s)",
                       ("admin", admin_password, "admin"))

        conn.commit()
        conn.close()

    def login(self):
        username = self.username_entry.get()
        password_hash = hashlib.sha256(self.password_entry.get().encode()).hexdigest()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, role FROM Users WHERE username = %s AND password_hash = %s",
                       (username, password_hash))
        result = cursor.fetchone()
        conn.close()

        if result:
            self.current_user, self.current_role = result
            messagebox.showinfo("Login", f"Logged in as {self.current_role}")
            self.tabs.select(self.card_tab if self.current_role != 'admin' else self.admin_tab)
        else:
            messagebox.showerror("Login", "Invalid credentials")

    def add_card(self):
        if not self.current_user:
            return messagebox.showerror("Error", "Login required")

        data = {k: v.get() for k, v in self.card_entries.items()}
        encrypted_number = fernet.encrypt(data["Card Number"].encode()).decode()
        encrypted_cvv = fernet.encrypt(data["CVV"].encode()).decode()

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO CreditCards (user_id, cardholder_name, card_number, expiration_date, cvv)
            VALUES (%s, %s, %s, %s, %s)
        """, (self.current_user, data["Cardholder Name"], encrypted_number, data["Expiration Date"], encrypted_cvv))
        conn.commit()
        conn.close()

        messagebox.showinfo("Success", "Card added")
        for entry in self.card_entries.values():
            entry.delete(0, tk.END)

    def view_cards(self):
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT cardholder_name, card_number FROM CreditCards WHERE user_id = %s", (self.current_user,))
        cards = cursor.fetchall()
        conn.close()

        top = tk.Toplevel(self.root)
        top.title("Your Cards")

        for name, enc_number in cards:
            decrypted = fernet.decrypt(enc_number.encode()).decode()
            masked = "**** **** **** " + decrypted[-4:]
            ttk.Label(top, text=f"{name}: {masked}").pack(pady=5)

    def view_all_users(self):
        if self.current_role != 'admin':
            return messagebox.showerror("Access Denied", "Admin only")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("SELECT user_id, username, role FROM Users")
        users = cursor.fetchall()
        conn.close()

        top = tk.Toplevel(self.root)
        top.title("All Users")

        for uid, name, role in users:
            ttk.Label(top, text=f"ID: {uid}, Username: {name}, Role: {role}").pack(pady=5)

    def view_all_cards(self):
        if self.current_role != 'admin':
            return messagebox.showerror("Access Denied", "Admin only")

        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT u.username, c.cardholder_name, c.card_number
            FROM CreditCards c
            JOIN Users u ON c.user_id = u.user_id
        """)
        cards = cursor.fetchall()
        conn.close()

        top = tk.Toplevel(self.root)
        top.title("All Cards")

        for user, name, enc_number in cards:
            decrypted = fernet.decrypt(enc_number.encode()).decode()
            masked = "**** **** **** " + decrypted[-4:]
            ttk.Label(top, text=f"User: {user}, {name}: {masked}").pack(pady=5)

if __name__ == '__main__':
    root = tk.Tk()
    app = CreditCardVault(root)
    root.mainloop()
