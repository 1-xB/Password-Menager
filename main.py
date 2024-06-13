import threading
from tkinter import messagebox
from customtkinter import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


class PasswordManager:
    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.master_password = None

    def create_master_key(self, master_password):
        salt = os.urandom(16)  # 16 bytes salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key, salt

    def load_master_key(self, salt, master_password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key

    def create_key(self, master_password, path, name):
        key_file_path = f"{path}/{name}.key"
        self.key, salt = self.create_master_key(master_password)
        with open(key_file_path, 'wb') as key_file:
            key_file.write(salt + b":" + self.key)

    def load_key(self, master_password, path):
        with open(path, 'rb') as key_file:
            data = key_file.read()
            salt, encrypted_key = data.split(b":")
            self.key = self.load_master_key(salt, master_password)

            if self.verify_password(master_password, salt, encrypted_key):
                print("Master password verified. Key loaded successfully.")
            else:
                print("Incorrect master password.")
                self.key = None

    def verify_password(self, master_password, salt, encrypted_key):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_attempt = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        return key_attempt == encrypted_key

    def create_password_file(self, path, name, initial_values=None):
        self.password_file = f"{path}/{name}.txt"

        if initial_values:
            with open(self.password_file, 'w') as file:
                for key, values in initial_values.items():
                    self.add_password(key, name, values[0], values[1], values[2])

    def load_password_file(self, path):
        self.password_file = path

        with open(path, 'r') as file:
            for line in file:
                site, mail, passw, url = line.strip().split(":")
                self.password_dict[site] = [
                    Fernet(self.key).decrypt(mail.encode()).decode(),
                    Fernet(self.key).decrypt(passw.encode()).decode(),
                    Fernet(self.key).decrypt(url.encode()).decode()
                ]

    def add_password(self, site, name, mail, password, url):
        self.password_dict[site] = [mail, password, url]
        with open(self.password_file, 'a+') as file:
            mail_encrypted = Fernet(self.key).encrypt(mail.encode()).decode()
            password_encrypted = Fernet(self.key).encrypt(password.encode()).decode()
            url_encrypted = Fernet(self.key).encrypt(url.encode()).decode()
            file.write(f"{site}:{mail_encrypted}:{password_encrypted}:{url_encrypted}\n")

    def get_password(self, site):
        return self.password_dict.get(site, [])

    def gui(self):
        window = CTk()
        window.title("Password Manager")
        window.geometry("400x400")

        header = CTkLabel(master=window, text="Your Passwords", font=("Arial", 20))
        header.pack(pady=20)

        for site, password in self.password_dict.items():
            text = f'{site}: {password}'
            label = CTkLabel(master=window, text=text, font=("Arial", 14))
            label.pack(pady=5)

        window.mainloop()


def main():
    pm = PasswordManager()
    passwords = {
        'Email': ['example@example', 'Email123', 'email.com'],
        'Youtube': ['example@example', 'Youtube123', 'Youtube.com'],
        'Facebook': ['example@example', 'Facebook123', 'Facebook.com'],
        'Instagram': ['example@example', 'Instagram123', 'Instagram.com'],
        'Twitter': ['example@example', 'Twitter123', 'Twitter.com']

    }

    def login_menu():
        def log_in():
            location = key_Entry.get()
            master_password = password_entry.get()

            if os.path.exists(location):
                files = os.listdir(location)
                key_file = None
                txt_file = None

                for file in files:
                    if file.endswith('.key'):
                        if key_file is None:
                            key_file = file
                        else:
                            messagebox.showerror('Error', 'There must not be more than one .key file in the folder.')
                            return
                    elif file.endswith('.txt'):
                        if txt_file is None:
                            txt_file = file
                        else:
                            messagebox.showerror('Error', 'There must not be more than one .txt file in the folder.')
                            return

                if key_file and txt_file:
                    try:
                        pm.load_key(master_password, f'{location}/{key_file}')
                        pm.load_password_file(f'{location}/{txt_file}')
                    except:
                        messagebox.showerror('Error', 'Incorrect master password.')
                        return

                    window.destroy()
                    threading.Thread(target=pm.gui).start()
                else:
                    messagebox.showerror('Error', 'Your password database is corrupted.')
            else:
                messagebox.showerror('Error', 'The path given does not exist. Enter a valid path.')

        def open_database():
            file = filedialog.askdirectory()
            key_Entry.delete(0,'end')
            key_Entry.insert(0,file)

        def create_db():
            window.destroy()
            thread = threading.Thread(target=createbase_menu)
            thread.start()

        def show_password():
            if password_entry.cget('show') == '*':
                password_entry.configure(show='')
                show_password_button.configure(text='Hide')
            else:
                password_entry.configure(show='*')
                show_password_button.configure(text='Show')

        window = CTk()
        window.title("Log in to Database")
        window.geometry('450x300')
        window.resizable(False, False)
        set_appearance_mode("dark")
        set_default_color_theme("green")

        frame = CTkFrame(master=window)
        frame.pack(pady=20, padx=60)

        open_db_label = CTkLabel(master=frame, text="Open Database", font=("Helvetica", 20))
        open_db_label.grid(row=0, column=0, columnspan=3, pady=10)

        password_label = CTkLabel(master=frame, text="Password:")
        password_label.grid(row=1, column=0, pady=5, padx=5)

        password_entry = CTkEntry(master=frame, show="*")
        password_entry.grid(row=1, column=1, pady=5, padx=5)

        show_password_button = CTkButton(master=frame, text="Show", command=show_password, width=10,
                                         font=('Helvetica', 11))
        show_password_button.grid(row=1, column=2, pady=5)

        key_label = CTkLabel(master=frame, text="Database folder:")
        key_label.grid(row=2, column=0, pady=5, padx=5)

        key_Entry = CTkEntry(master=frame)
        key_Entry.grid(row=2, column=1, pady=20)

        open_button = CTkButton(master=frame, width=10, text='Open', command=open_database)
        open_button.grid(row=2, column=2)

        login_button = CTkButton(master=frame, width=10, text='Log in', command=log_in)
        login_button.grid(row=3, column=0, columnspan=3)

        CTkLabel(master=window, text="Don't you have your own password database?", font=("Helvetica", 12)).pack()

        createbase_button = CTkButton(master=window, text="Create Database", font=("Helvetica", 12), width=10,
                                      command=create_db)
        createbase_button.pack(pady=10)

        window.mainloop()

    def createbase_menu():
        def show_password():
            if password_entry.cget('show') == '*':
                password_entry.configure(show='')
                show_password_button.configure(text='Hide')
            else:
                password_entry.configure(show='*')
                show_password_button.configure(text='Show')

        def select_location():
            location = filedialog.askdirectory()
            if location:
                location_entry.delete(0, END)
                location_entry.insert(0, location)

        def login_database():
            window.destroy()
            login_menu()

        def create_database():
            name = name_entry.get()
            password = password_entry.get()
            location = location_entry.get()
            pm.create_key(password, location, name, )
            pm.create_password_file(location,name, passwords)
            window.destroy()
            pm.gui()

        window = CTk()
        window.title('Create Database')
        window.geometry('420x320')
        window.resizable(False, False)

        frame = CTkFrame(master=window)
        frame.pack(pady=20, padx=60)

        create_db_label = CTkLabel(master=frame, text="Create Database", font=("Helvetica", 20))
        create_db_label.grid(row=0, column=0, columnspan=3, pady=5)

        name_label = CTkLabel(master=frame, text="Database name:")
        name_label.grid(row=1, column=0, pady=5, padx=1)

        name_entry = CTkEntry(master=frame)
        name_entry.grid(row=1, column=1, columnspan=2, pady=5, padx=2)

        password_label = CTkLabel(master=frame, text="Password:")
        password_label.grid(row=2, column=0, pady=5)

        password_entry = CTkEntry(master=frame, show="*")
        password_entry.grid(row=2, column=1, pady=5, padx=2)

        show_password_button = CTkButton(master=frame, text="Show", command=show_password, width=10,
                                         font=('Helvetica', 11))
        show_password_button.grid(row=2, column=2, pady=5)

        location_label = CTkLabel(master=frame, text="Location:")
        location_label.grid(row=3, column=0, pady=5)

        location_entry = CTkEntry(master=frame)
        location_entry.grid(row=3, column=1, pady=5)

        select_location_button = CTkButton(master=frame, width=10, text='Select', command=select_location)
        select_location_button.grid(row=3, column=2, pady=5, padx=1)

        create_database_button = CTkButton(master=frame, width=10, text='Create', command=create_database)
        create_database_button.grid(row=4, column=0, columnspan=3, padx=10, pady=10)

        CTkLabel(master=window, text='Do you already have a password database?').pack()

        login_to_database = CTkButton(master=window, width=1, text='Log in to database', command=login_database)
        login_to_database.pack(pady=10)

        window.mainloop()

    login_menu()


if __name__ == '__main__':
    main()
