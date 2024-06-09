from customtkinter import *
import subprocess
import threading
import cryptography
from cryptography.fernet import Fernet
import json
import os
from shlex import quote as shlex_quote


def main():
    def log_in():
        pass

    def open_database():
        file = filedialog.askopenfilename()

    def create_db():
        def run():
            subprocess.run(['python', 'create_data.py'], capture_output=True, text=True)
        thread = threading.Thread(target=run)
        thread.start()
    # Tworzenie głównego okna
    window = CTk()
    window.title("Log in to Database")
    window.geometry('400x300')
    window.resizable(False, False)
    set_appearance_mode("dark")  # Możliwości: "light", "dark"
    set_default_color_theme("green")  # Możliwości: "blue", "green", "dark-blue"

    # Tworzenie ramki
    frame = CTkFrame(master=window)
    frame.pack(pady=20, padx=60)
    # Tworzenie etykiety "Open Database"
    open_db_label = CTkLabel(master=frame, text="Open Database", font=("Helvetica", 20))
    open_db_label.grid(row=0, column=0, columnspan=3, pady=10)

    # Tworzenie etykiety "Password" i pola na hasło
    password_label = CTkLabel(master=frame, text="Password:")
    password_label.grid(row=1, column=0, pady=5, padx=5)

    password_entry = CTkEntry(master=frame, show="*")
    password_entry.grid(row=1, column=1, pady=5, padx=5)

    # Tworzenie Combobox
    key_label = CTkLabel(master=frame, text="Key:")
    key_label.grid(row=2, column=0, pady=5, padx=5)

    options = ['(None)', ]
    key_combo = CTkComboBox(master=frame, values=options)
    key_combo.grid(row=2, column=1, pady=20)

    #  przycisk open

    open_button = CTkButton(master=frame, width=1, text='open', command=open_database)
    open_button.grid(row=2, column=2)

    #  przycisk login
    open_button = CTkButton(master=frame, width=1, text='Log in', command=log_in)
    open_button.grid(row=3, column=0, columnspan=3)

    CTkLabel(master=window, text="Don't you have your own password database?", font=("Helvetica", 12)).pack()

    createbase_button = CTkButton(master=window, text="Create Database", font=("Helvetica", 12), width=1, command=create_db)
    createbase_button.pack(pady=10)

    # Uruchomienie pętli głównej aplikacji
    window.mainloop()


if __name__ == '__main__':
    main()
