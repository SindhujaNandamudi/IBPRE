from tkinter import *
import sqlite3
import hashlib
import secrets
from cryptography.fernet import Fernet
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

conn = sqlite3.connect('user_data.db')
c = conn.cursor()
c.execute('CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT,key TEXT)')
c.execute('CREATE TABLE IF NOT EXISTS shared_with (data_holder_id TEXT, shared_with TEXT, rekey TEXT, FOREIGN KEY(data_holder_id) REFERENCES users(username))')
txt=""
self_id=""
def create_main_interface():
    # Create the main window
    root = Tk()
    root.title("Login Interface")

    # Create the login form
    login_frame = Frame(root, padx=50, pady=50)

    # Create login widgets
    username_label = Label(login_frame, text="User ID:")
    username_label.pack()

    username_entry = Entry(login_frame)
    username_entry.pack()

    password_label = Label(login_frame, text="Password:")
    password_label.pack()

    password_entry = Entry(login_frame, show="*")
    password_entry.pack()
    login_error_label = Label(login_frame, fg="red")
    signup_error_label = Label(login_frame, fg="red")
    def login():
        username = username_entry.get()
        password = password_entry.get()
        global self_id
        self_id=username
        # TODO: Add authentication logic here
            # Hash the entered password
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        # Check if the username and hashed password match the database
        c.execute('SELECT * FROM users WHERE username=? AND password=?', (username, hashed_password))
        user = c.fetchone()

        if user is not None:
            # Show the share data frame if the user is authenticated
            login_frame.pack_forget()
            root.destroy()
            # Destroy the login form and show the main interface
            show_main_interface()
        else:
            # Show an error message if the user is not authenticated
            login_error_label.config(text="Invalid username or password")
            login_error_label.pack()
        

    login_button = Button(login_frame, text="Login", command=login)
    login_button.pack(pady=10)

    def signup():
        # Get the entered username and password
        new_username = username_entry.get()
        new_password = password_entry.get()

        # Hash the entered password
        hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
        key=os.urandom(16)
        # Add the new user to the database
        try:
            c.execute('INSERT INTO users (username, password, key) VALUES (?, ?, ?)', (new_username, hashed_password,key))
            conn.commit()
            signup_error_label.config(text="User created successfully")
            signup_error_label.pack()
        except sqlite3.IntegrityError:
            signup_error_label.config(text="Username already exists")
            signup_error_label.pack()

    signup_button = Button(login_frame, text="Sign Up", command=signup)
    signup_button.pack(pady=10)
    def menu_click() :
        pass
    def button_select(m):
        global txt
        txt=m
        print(txt)

    def add_user() :
        window2=Tk()
        window2.title("Add users")
        add_user_frame=Frame(window2,padx=50,pady=50)
        my_listbox = Listbox(add_user_frame, selectmode=MULTIPLE)
        c.execute('SELECT DISTINCT username FROM users ')
        users = c.fetchall()
        for user in users:
            my_listbox.insert(END, user[0])
        my_listbox.pack()
        def save() :
            selected_users = my_listbox.curselection()
            for i in selected_users:
                key=os.urandom(16)
                shared_with_username = my_listbox.get(i)
                c.execute('INSERT INTO shared_with (data_holder_id, shared_with, key) VALUES (?, ?, ?)', (self_id, shared_with_username,key))
                conn.commit()
        save_button = Button(add_user_frame, text="Save", command=save)
        save_button.pack(pady=10)
        add_user_frame.pack()

    def del_user() :
        window3=Tk()
        window3.title("Del users")
        del_user_frame=Frame(window3,padx=50,pady=50)
        my_listbox = Listbox(del_user_frame, selectmode=MULTIPLE)
        print(self_id)
        c.execute('SELECT shared_with FROM shared_with JOIN users ON shared_with.data_holder_id = users.username WHERE users.username = ?',(self_id,))
        users = c.fetchall()
        for user in users:
            my_listbox.insert(END, user[0])
        my_listbox.pack()
        def save() :
            selected_users = my_listbox.curselection()
            for i in selected_users:
                shared_with_username = my_listbox.get(i)
                c.execute('DELETE FROM shared_with WHERE data_holder_id = ? AND shared_with=?', (self_id, shared_with_username))
                conn.commit()
        save_button = Button(del_user_frame, text="Save", command=save)
        save_button.pack(pady=10)
        del_user_frame.pack()

    def show_main_interface():
        # Create the main interface widgets
        def download():
            '''window4=Tk()
            window4.title("Data download")
            data_dld_frame=Frame(window4,padx=100,pady=100)
            dld_label = Label(data_dld_frame, text="Select user:")
            dld_label.pack()
            selected_option = StringVar()
            selected_option.set("self")
            c.execute('SELECT shared_with FROM shared_with WHERE data_holder_id=?',(self_id,))
            options=[row[0] for row in c.fetchall()]
            dropdown = OptionMenu(window4, selected_option, *options,value="")
            dropdown.pack()
            def print_option():
                print(selected_option.get())
            # Create a button to trigger the print function
            button = Button(data_dld_frame, text="Download", command=print_option)
            button.pack()
            data_dld_frame.pack()'''
            window4 = Tk()
            window4.title("Data download")
            data_dld_frame = Frame(window4, padx=100, pady=100)
            data_dld_frame.grid(row=0, column=0)
            dld_label = Label(data_dld_frame, text="Select user:")
            dld_label.grid(row=0, column=0)
            selected_option = StringVar()
            selected_option.set("self")
            c.execute('SELECT data_holder_id FROM shared_with WHERE shared_with=?', (self_id,))
            options = [row[0] for row in c.fetchall()]
            dropdown = OptionMenu(data_dld_frame, selected_option, *options, value="")
            dropdown.grid(row=0, column=1, columnspan=2)
            def download_file():
                print(selected_option.get())
            download_button = Button(data_dld_frame, text="Download", command=download_file)
            download_button.grid(row=1, column=0, columnspan=2)
            

        def encrypt(plaintext):
            c.execute('SELECT key FROM users WHERE username=?',(self_id,))
            key=c.fetchone()[0]
            print(key)
            cipher = AES.new(key, AES.MODE_CBC)
            padded_plaintext = pad(plaintext.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_plaintext)
            iv = cipher.iv
            return ciphertext, iv
        
        def upload() :
            data=text_box.get(1.0,END)
            encrypted_data,iv=encrypt(data)
            upload_label.config(text="Uploaded successfully")
            upload_label.pack()

        window = Tk()
        window.title("Login Interface")
        menu_frame = Frame(window, bg="gray", width=100, height=300)
        menu_frame.pack(side="left", fill="y")
        # Create the menu label
        menu_label = Label(menu_frame, text="Menu", bg="gray", fg="white", font=("Helvetica", 16))
        menu_label.pack(side="top", pady=10)

        # Create the menu items
        download_button = Button(menu_frame, text="download", width=10, command=download)
        download_button.pack(side="top", pady=5)
        add_user_button = Button(menu_frame, text="Add user", width=10, command=add_user)
        add_user_button.pack(side="top", pady=5)
        del_user_button = Button(menu_frame, text="Del user", width=10, command=del_user)
        del_user_button.pack(side="top", pady=5)
        global txt,self_id
        # Create the content frame
        content_frame = Frame(window, bg="white", width=400, height=300)
        content_frame.pack(side="right", fill="both", expand=True)

        # Create the label and text box
        label = Label(content_frame, text="Enter text:")
        label.pack(side="top", padx=10, pady=10)

        text_box = Text(content_frame, height=5)
        text_box.pack(side="top", padx=10, pady=10, fill="both", expand=True)
        upload_button = Button(content_frame, text="UPLOAD", width=10, command=upload)
        upload_button.pack(side="top", pady=5)
        upload_label = Label(content_frame, fg="red")


    # Start the main loop
    login_frame.pack()
    root.mainloop()

create_main_interface()
