import threading
from tkinter import messagebox, Listbox
from customtkinter import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import os


def create_master_key(master_password):
    salt = os.urandom(128)  # 16 bytes salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    return key, salt


class PasswordManager:
    def __init__(self):
        self.URL_Listbox = None
        self.password_Listbox = None
        self.email_Listbox = None
        self.title_Listbox = None
        self.frame = None
        self.window = None
        self.key = None
        self.password_file = None
        self.password_dict = {}
        self.master_password = None
        self.logged = False

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
        self.key, salt = create_master_key(master_password)
        with open(key_file_path, 'wb') as key_file:
            key_file.write(salt + b":" + self.key)

    def load_key(self, master_password, path):
        with open(path, 'rb') as key_file:
            data = key_file.read()
            salt, encrypted_key = data.split(b":", 1)  # Dzielenie tylko na pierwszym znaku ":"
            self.key = self.load_master_key(salt, master_password)

            if self.verify_password(master_password, salt, encrypted_key):
                print("Master password verified. Key loaded successfully.")
                self.logged = True
            else:
                print("Incorrect master password.")
                messagebox.showerror('Error', 'Incorrect master password.')
                self.key = None

    def verify_password(self, master_password, salt, encrypted_key):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key_attempt = base64.urlsafe_b64encode(kdf.derive(master_password.encode())).decode()
        return key_attempt == encrypted_key.decode()

    def create_password_file(self, path, name, initial_values=None):
        self.password_file = f"{path}/{name}.txt"

        if initial_values:
            with open(self.password_file, 'w') as file:
                for key, values in initial_values.items():
                    self.add_password(key, values[0], values[1], values[2])

    def load_password_file(self, path):
        self.password_file = path

        with open(path, 'r') as file:
            for line in file:
                parts = line.strip().split(":")
                if len(parts) != 4:
                    print(f"Invalid format in password file: {line}")
                    continue

                site, mail, passw, url = parts
                if self.key is None:
                    print("Key not loaded. Cannot decrypt passwords.")
                    return

                try:
                    decrypted_mail = Fernet(self.key).decrypt(mail.encode()).decode()
                    decrypted_passw = Fernet(self.key).decrypt(passw.encode()).decode()
                    decrypted_url = Fernet(self.key).decrypt(url.encode()).decode()
                except Exception as e:
                    print(f"Decryption error: {e}")
                    continue

                self.password_dict[site] = [decrypted_mail, decrypted_passw, decrypted_url]

    def add_password(self, site, mail, password, url):
        self.password_dict[site] = [mail, password, url]
        with open(self.password_file, 'a+') as file:
            mail_encrypted = Fernet(self.key).encrypt(mail.encode()).decode()
            password_encrypted = Fernet(self.key).encrypt(password.encode()).decode()
            url_encrypted = Fernet(self.key).encrypt(url.encode()).decode()
            file.write(f"{site}:{mail_encrypted}:{password_encrypted}:{url_encrypted} \n")

    def get_password(self, site):
        return self.password_dict.get(site, [])

    def add_entry(self):
        def add():
            title = Title_entry.get()
            email = Email_entry.get()
            password = Password_entry.get()
            url = URL_entry.get()
            if title and email and password and url:
                self.add_password(title, email, password, url)
                window_add_entry.destroy()
                self.window.update()
                self.gui_update()
            else:
                messagebox.showerror('Error', 'Please fill all fields.')
        window_add_entry = CTk()
        window_add_entry.geometry('400x300')
        window_add_entry.resizable(False, False)
        CTkLabel(master=window_add_entry, text='Add Entry', font=("Arial", 20)).pack()
        frame_main = CTkFrame(master=window_add_entry)
        frame_main.pack(pady=10)

        # title
        CTkLabel(master=frame_main, text='Title').grid(row=0, column=0, sticky="NSEW")
        Title_entry = CTkEntry(master=frame_main)
        Title_entry.grid(row=0, column=1, padx=10, pady=10, sticky="NSEW")

        # email
        CTkLabel(master=frame_main, text='Email/Username').grid(row=1, column=0, sticky="NSEW", pady=10)
        Email_entry = CTkEntry(master=frame_main)
        Email_entry.grid(row=1, column=1, padx=10, pady=10, sticky="NSEW")

        # password
        CTkLabel(master=frame_main, text='Password').grid(row=2, column=0, sticky="NSEW", pady=10)
        Password_entry = CTkEntry(master=frame_main)
        Password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="NSEW")

        # url
        CTkLabel(master=frame_main, text='URL').grid(row=3, column=0, sticky="NSEW", pady=10)
        URL_entry = CTkEntry(master=frame_main)
        URL_entry.grid(row=3, column=1, padx=10, pady=10, sticky="NSEW")

        # create
        button_create = CTkButton(master=window_add_entry, text='Add', command=add)
        button_create.pack()

        window_add_entry.mainloop()

    def gui_update(self):
        self.title_Listbox.delete(0, 'end')
        self.email_Listbox.delete(0, 'end')
        self.password_Listbox.delete(0, 'end')
        self.URL_Listbox.delete(0, 'end')
        for item in self.password_dict.items():
            self.title_Listbox.insert(END, item[0])
            self.email_Listbox.insert(END, item[1][0])
            self.password_Listbox.insert(END, item[1][1])
            self.URL_Listbox.insert(END, item[1][2])


    def gui(self):
        self.window = CTk()
        self.window.title("Password Manager")
        self.window.geometry("500x400")

        header = CTkLabel(master=self.window, text="Your Passwords", font=("Arial", 20))
        header.grid(row=0, column=0, columnspan=3, sticky="NSEW")

        add_entry_button = CTkButton(master=self.window, text="Add Entry", font=("Arial", 12), width=10,
                                     command=self.add_entry)
        add_entry_button.grid(row=1, column=0, pady=10, sticky="NSEW")

        self.frame = CTkFrame(master=self.window)
        self.frame.grid(row=2, column=0, columnspan=3, pady=10, sticky="NSEW")


        CTkLabel(master=self.frame, text='Title').grid(row=0, column=0, sticky="NSEW")
        CTkLabel(master=self.frame, text='Email/Username').grid(row=0, column=1, sticky="NSEW")
        CTkLabel(master=self.frame, text='Password').grid(row=0, column=2, sticky="NSEW")
        CTkLabel(master=self.frame, text='URL').grid(row=0, column=3, sticky="NSEW")

        # title
        CTkLabel(master=self.frame, text='Title').grid(row=0, column=0, sticky="NSEW")
        self.title_Listbox = Listbox(self.frame, bg='#242424', borderwidth=0, highlightthickness=0, fg='white', selectbackground='#353535')
        self.title_Listbox.grid(row=1, column=0)

        # email
        CTkLabel(master=self.frame, text='Email/Username').grid(row=0, column=1, sticky="NSEW")
        self.email_Listbox = Listbox(self.frame, bg='#242424', borderwidth=0, highlightthickness=0, fg='white', selectbackground='#353535')
        self.email_Listbox.grid(row=1, column=1)

        # password
        CTkLabel(master=self.frame, text='Password').grid(row=0, column=2, sticky="NSEW")
        self.password_Listbox = Listbox(self.frame, bg='#242424', borderwidth=0, highlightthickness=0, fg='white', selectbackground='#353535')
        self.password_Listbox.grid(row=1, column=2)

        # URL
        CTkLabel(master=self.frame, text='URL').grid(row=0, column=3, sticky="NSEW")
        self.URL_Listbox = Listbox(self.frame, bg='#242424', borderwidth=0, highlightthickness=0, fg='white', selectbackground='#353535')
        self.URL_Listbox.grid(row=1, column=3)



        scrollbar = CTkScrollbar(master=self.frame, orientation='vertical', command=self.on_scroll)
        scrollbar.grid(row=1, column=4, sticky="NS")

        self.title_Listbox.config(yscrollcommand=scrollbar.set)
        self.email_Listbox.config(yscrollcommand=scrollbar.set)
        self.password_Listbox.config(yscrollcommand=scrollbar.set)
        self.URL_Listbox.config(yscrollcommand=scrollbar.set)

        self.gui_update()

        self.window.mainloop()

    def on_scroll(self, *args):
        self.title_Listbox.yview(*args)
        self.email_Listbox.yview(*args)
        self.password_Listbox.yview(*args)
        self.URL_Listbox.yview(*args)






def main():
    pm = PasswordManager()
    passwords = {
        'Email': ['example@example', 'Email123', 'email.com'],
        'Youtube': ['example@example', 'Youtube123', 'Youtube.com'],
        'Facebook': ['example@example', 'Facebook123', 'Facebook.com'],
        'Instagram': ['example@example', 'Instagram123', 'Instagram.com'],
        'Twitter': ['example@example', 'Twitter123', 'Twitter.com']

    }

    def open_window_login():
        window_c.destroy()
        login_menu()

    def open_window_create():
        window_l.destroy()
        createbase_menu()

    def login_menu():
        global window_l

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

                    pm.load_key(master_password, f'{location}/{key_file}')
                    if pm.logged:
                        pm.load_password_file(f'{location}/{txt_file}')
                        window_l.destroy()
                        threading.Thread(target=pm.gui).start()
                else:
                    messagebox.showerror('Error', 'Your password database is corrupted.')
            else:
                messagebox.showerror('Error', 'The path given does not exist. Enter a valid path.')

        def open_database():
            file = filedialog.askdirectory()
            key_Entry.delete(0, 'end')
            key_Entry.insert(0, file)

        def show_password():
            if password_entry.cget('show') == '*':
                password_entry.configure(show='')
                show_password_button.configure(text='Hide')
            else:
                password_entry.configure(show='*')
                show_password_button.configure(text='Show')

        window_l = CTk()
        window_l.title("Log in to Database")
        window_l.geometry('450x300')
        window_l.resizable(False, False)
        set_appearance_mode("dark")
        set_default_color_theme("green")

        frame = CTkFrame(master=window_l)
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

        CTkLabel(master=window_l, text="Don't you have your own password database?", font=("Helvetica", 12)).pack()

        createbase_button = CTkButton(master=window_l, text="Create Database", font=("Helvetica", 12), width=10,
                                      command=open_window_create)
        createbase_button.pack(pady=10)

        window_l.mainloop()

    def createbase_menu():
        global window_c

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


        def create_database():
            name = name_entry.get()
            password = password_entry.get()
            location = location_entry.get()
            pm.create_key(password, location, name, )
            pm.create_password_file(location, name, passwords)
            window_c.destroy()
            pm.gui()

        window_c = CTk()
        window_c.title('Create Database')
        window_c.geometry('420x320')
        window_c.resizable(False, False)

        frame = CTkFrame(master=window_c)
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

        CTkLabel(master=window_c, text='Do you already have a password database?').pack()

        login_to_database = CTkButton(master=window_c, width=1, text='Log in to database', command=open_window_login)
        login_to_database.pack(pady=10)

        window_c.mainloop()

    login_menu()


if __name__ == '__main__':
    main()