import threading
from customtkinter import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


class PasswordMenager():
    def __init__(self):
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.master_password = None

    def create_master_key(self, master_password):
        """salt - losowa wartość dodawana do danych wejściowych przed ich przetworzeniem przez funkcję haszującą.
         Sól jest używana głównie w kontekście haszowania haseł,
          aby zwiększyć bezpieczeństwo przechowywanych haseł i utrudnić ataki"""
        salt = os.urandom(128)  # 128 bitowy salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # To długość wygenerowanego klucza w bajtach. W tym przypadku jest to 32 bajty (256 bitów),
            salt=salt,
            iterations=1000000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))  # generuje klucz
        return key, salt

    def load_master_key(self, salt, master_password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # To długość wygenerowanego klucza w bajtach. W tym przypadku jest to 32 bajty (256 bitów),
            salt=salt,
            iterations=1000000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))  # generuje klucz
        return key

    def create_key(self, master_password, path, name, ):
        l = f"{path}/{name}.key"
        self.key, salt = self.create_master_key(master_password)
        with open(l, 'wb') as key:
            key.write(salt + b":" + self.key)

    def load_key(self, master_password, path):
        with open(path + '.key', 'rb') as key_file:
            data = key_file.read()
            salt, encrypted_key = data.split(b":")
            self.key = self.load_master_key(master_password, salt)

            if self.verify_password(master_password, salt, encrypted_key):
                self.key = self.load_master_key(master_password, salt)
                print("Master password verified. Key loaded successfully.")
            else:
                print("Incorrect master password.")
                self.key = None

    def verify_password(self, master_password, salt, encrypted_key):
        # Wygenerowanie klucza na podstawie podanego hasła głównego i soli
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=1000000,
            backend=default_backend()
        )
        key_attempt = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        # Porównanie wygenerowanego klucza z zaszyfrowanym kluczem z pliku
        return key_attempt == encrypted_key

    def create_password_file(self, path, name, initial_values=None):
        self.password_file = path

        if initial_values is not None:
            for key, values in initial_values.items():
                self.add_password(key, name, values[0], values[1], values[2])

    def load_password_file(self, path):
        self.password_file = path

        with open(path, 'r') as file:
            for line in file:
                site, mail, passw, url = line.strip().split(":")
                self.password_dict[site] = []
                self.password_dict[site].append(Fernet(self.key).decrypt(mail.encode()).decode())
                self.password_dict[site].append(Fernet(self.key).decrypt(passw.encode()).decode())
                self.password_dict[site].append(Fernet(self.key).decrypt(url.encode()).decode())

    def add_password(self, site, name, mail, password, url):
        self.password_dict[site] = [mail, password, url]
        with open(f'{self.password_file}/{name}', 'a+') as file:
            mail = Fernet(self.key).encrypt(mail.encode())
            pasw = Fernet(self.key).encrypt(password.encode())
            url = Fernet(self.key).encrypt(url.encode())
            file.write(site + ":" + mail + ':' + pasw + ':' + url + '\n')

    def get_password(self, site):
        return self.password_dict[site]

    def gui(self):
        window = CTk()  # Tworzenie głównego okna
        window.title("Password Manager")  # Ustawienie tytułu okna
        window.geometry("400x400")  # Ustawienie rozmiaru okna

        # Dodanie nagłówka
        header = CTkLabel(master=window, text="Your Passwords", font=("Arial", 20))
        header.pack(pady=20)

        # Dodanie etykiet z hasłami
        for i in self.password_dict:
            password = self.get_password(i)
            text = f'{i}: {password}'
            label = CTkLabel(master=window, text=text, font=("Arial", 14))
            label.pack(pady=5)

        window.mainloop()  # Uruchamianie głównej pętli aplikacji


def main():
    pm = PasswordMenager()
    passwords = {
        'Email': ['example@example', 'Email123', 'email.com'],
        'Youtube': ['example@example', 'Youtube123', 'Youtube.com'],
        'Facebook': ['example@example', 'Facebook123', 'Facebook.com'],
        'Instagram': ['example@example', 'Instagram123', 'Instagram.com'],
        'Twitter': ['example@example', 'Twitter123', 'Twitter.com']

    }

    def login_menu():
        def log_in():
            pass

        def open_database():
            file = filedialog.askdirectory()

            if file:
                options = [file]
                key_combo.configure(values=options)
                key_combo.set(file)

        def create_db():
            window.destroy()
            thread = threading.Thread(target=createbase_menu())
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

        options = ['(None)', ]
        key_combo = CTkComboBox(master=frame, values=options)
        key_combo.grid(row=2, column=1, pady=20)

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
