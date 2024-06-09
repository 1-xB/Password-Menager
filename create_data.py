from customtkinter import *
from PIL import Image, ImageTk


def main():
    def show_password():
        if password_entry.cget('show') == '*':
            password_entry.configure(show='')
            show_password_button.configure(text='Hide')
        else:
            password_entry.configure(show='*')
            show_password_button.configure(text='Show')

    window = CTk()
    window.title('Create Database')
    window.geometry('420x300')
    window.resizable(False, False)
    set_appearance_mode("dark")  # Możliwości: "light", "dark"
    set_default_color_theme("green")  # Możliwości: "blue", "green", "dark-blue"

    frame = CTkFrame(master=window, width=10)
    frame.pack(pady=20, padx=60)

    create_db_label = CTkLabel(master=frame, text="Create Database", font=("Helvetica", 20))
    create_db_label.grid(row=0, column=0, columnspan=3, pady=5)  # Zmieniono columnspan na 3

    # Nazwa
    name_label = CTkLabel(master=frame, text="Database name:")
    name_label.grid(row=1, column=0, pady=5, padx=1)

    name_entry = CTkEntry(master=frame)
    name_entry.grid(row=1, column=1, columnspan=2, pady=5, padx=2)  # Zmieniono columnspan na 2

    # Hasło
    password_label = CTkLabel(master=frame, text="Password:")
    password_label.grid(row=2, column=0, pady=5)

    password_entry = CTkEntry(master=frame, show="*")
    password_entry.grid(row=2, column=1, pady=5, padx=2)  # Zmieniono columnspan na 1

    show_password_button = CTkButton(master=frame, text="Show", command=show_password, width=1, font=('Helvetica', 11))
    show_password_button.grid(row=2, column=2, pady=5)

    # Lokalizacja
    location_label = CTkLabel(master=frame, text="Location:")
    location_label.grid(row=3, column=0, pady=5)

    options = ['(None)', ]
    key_combo = CTkComboBox(master=frame, values=options)
    key_combo.grid(row=3, column=1, pady=5)

    # Przycisk select
    open_button = CTkButton(master=frame, width=1, text='select', font=('Helvetica', 11))
    open_button.grid(row=3, column=2, pady=5, padx=1)  # Umieszczony w kolumnie 2

    window.mainloop()


if __name__ == "__main__":
    main()
