from cryptography import x509
from cryptography.hazmat. backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives. serialization import (Encoding,
                                                           PrivateFormat, NoEncryption)

import socket
import os
import tkinter as tk
from tkinter import *
from tkinter import font
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
import sys

import threading
USERNAME = ""
OTHER_USERNAME =""
DELIMETER = b"$END_MESSAGE$"
other_user_cert = None
NEW_SOCKET = NONE
DARK_GREY = '#4C4E52'
MEDIUM_GREY = 'black'
OCEAN_BLUE = '#4C4E52'
WHITE = "white"
FONT = ("Helvetica", 17)
BUTTON_FONT = ("Helvetica", 15)
SMALL_FONT = ("Helvetica", 13)


def request_certificate(s: socket):
    if os.path.exists(f"./{USERNAME}.key"):
        return
    send_option(s, b"OP_REQ_CERT")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f'USER:{USERNAME}'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Menlo Park'),
    ]))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend())

    # write the private key to the current directory
    with open(f'./{USERNAME}.key', 'wb') as f:
        f.write(private_key.private_bytes(Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL, NoEncryption()))

    # send the request to the ca server
    data = bytearray()
    data.extend(USERNAME.encode("utf-8") + DELIMETER)
    data.extend(request.public_bytes(Encoding.PEM))
    s.sendall(bytes(data))


def load_certificate(cert_data):
    certificate = x509.load_pem_x509_certificate(
        cert_data, default_backend())
    return certificate


def encrypt_message(message: str, certificate):
    public_key = certificate.public_key()
    encrypted_message = public_key.encrypt(
        bytes(message, 'utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_message


def decrypt_message(ciphertext):
    pem_key = open(USERNAME + ".key", 'rb').read()
    private_key = serialization.load_pem_private_key(
        pem_key, password=None, backend=default_backend())
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def read_message(client: socket):
    chunk = client.recv(4096)
    return chunk
def send_option(s: socket, option: bytes):
    s.sendall(option)
    data = s.recv(1024)


def init_socket():
    host = "127.0.0.1"
    port = 65433
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        request_certificate(s)
        # while True:
        #     print("Select an operation:")
        #     print("1. Initiate a communication with someone")
        #     print("2. Accept a communication with someone")
        #     option = int(input())
        #     if option == 1:
        #         send_option(s, b"OP_INIT_COMM")
        #         initiate_communication(s)
        #     elif option == 2:
        #         send_option(s, b"OP_ACC_COMM")
        #         accept_communication(s)
        #     else:
        #         print("Option not supported!")
class GUI :
    def __init__(self):
        # chat window which is currently hidden
        self.Window = Tk()
        self.Window.withdraw()
 
        # login window
        self.login = Toplevel()
        # set the title
        self.login.title("Login")
        self.login.resizable(width=False,
                             height=False)
        self.login.configure(width=600,
                             height=300)
        # create a Label
        self.pls = Label(self.login,
                         text="Please enter your username to continue",
                         justify=CENTER,
                         font="Helvetica 14 bold")
 
        self.pls.place(relheight=0.15,
                       relx=0.2,
                       rely=0.07)
        # create a Label
        self.labelName = Label(self.login,
                               text="Name: ",
                               font="Helvetica 12")
 
        self.labelName.place(relheight=0.2,
                             relx=0.1,
                             rely=0.2)
 
        # create a entry box for
        # tyoing the message
        self.entryName = Entry(self.login,
                               font="Helvetica 14")
 
        self.entryName.place(relwidth=0.4,
                             relheight=0.12,
                             relx=0.35,
                             rely=0.2)
 
        # set the focus of the cursor
        self.entryName.focus()
 
        # create a Continue Button
        # along with action
        self.go = Button(self.login,
                         text="CONTINUE",
                         font="Helvetica 14 bold",
                         command=lambda: self.switchToChatMenu(self.entryName.get()))
 
        self.go.place(relx=0.4,
                      rely=0.55)
        
        self.Window.mainloop()
    def layout(self, username):
        self.username = username
        self.Window.deiconify()
        self.Window.geometry("750x900")
        self.Window.title(USERNAME)
        self.Window.resizable(False, False)
        self.Window.grid_rowconfigure(0, weight=1)
        self.Window.grid_rowconfigure(1, weight=4)
        self.Window.grid_rowconfigure(2, weight=1)
        self.top_frame = tk.Frame(self.Window, width=600, height=100, bg=DARK_GREY)
        self.top_frame.grid(row=0, column=0, sticky=tk.NSEW)
        self.middle_frame = tk.Frame(self.Window, width=600, height=400, bg=MEDIUM_GREY)
        self.middle_frame.grid(row=1, column=0, sticky=tk.NSEW)

        self.bottom_frame = tk.Frame(self.Window, width=600, height=100, bg=DARK_GREY)
        self.bottom_frame.grid(row=2, column=0, sticky=tk.NSEW)

        self.username_label = tk.Label(self.top_frame, text="Enter friend's username :", font=FONT, bg=DARK_GREY, fg=WHITE)
        self.username_label.pack(side=tk.LEFT, padx=10)

        self.username_textbox = tk.Entry(self.top_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=23)
        self.username_textbox.pack(side=tk.LEFT)

        self.username_button = tk.Button(self.top_frame, text="Join", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,command=lambda:self.handleConnection(self.username_textbox.get()))
        self.username_button.pack(side=tk.LEFT, padx=15)

        self.message_textbox = tk.Entry(self.bottom_frame, font=FONT, bg=MEDIUM_GREY, fg=WHITE, width=38)
        self.message_textbox.pack(side=tk.LEFT, padx=10)

        self.message_button = tk.Button(self.bottom_frame, text="Send", font=BUTTON_FONT, bg=OCEAN_BLUE, fg=WHITE,command=lambda:self.send_message())
        self.message_button.pack(side=tk.LEFT, padx=10)

        self.message_box = scrolledtext.ScrolledText(self.middle_frame, font=SMALL_FONT, bg=MEDIUM_GREY, fg=WHITE, width=67, height=26.5)
        self.message_box.config(state=tk.DISABLED)
        self.message_box.pack(side=tk.TOP)

    def switchToChatMenu(self , username):
        global USERNAME
        USERNAME = username
        init_socket()
        self.login.destroy()
        self.layout(username)

    def add_message(self , message):
        self.message_box.config(state=tk.NORMAL)
        self.message_box.insert(tk.END, message + '\n')
        self.message_box.config(state=tk.DISABLED) 

    def recv(self ,socket, other_username):
        # receive data stream. it won't accept data packet greater than 1024 bytes
        while True:
            data = read_message(socket)
            if data:
                self.add_message(f'[{other_username}] :' + decrypt_message(ciphertext=data).decode('utf-8'))

    def initiate_communication(self, s: socket):
        new_host = '127.0.0.1'
        new_port = '9091'
        data = bytearray()
        data.extend(USERNAME.encode('utf-8') + DELIMETER)
        data.extend(OTHER_USERNAME.encode('utf-8') + DELIMETER)
        data.extend(new_host.encode('utf-8') + DELIMETER)
        data.extend(new_port.encode('utf-8'))
        s.sendall(data)
        certificate = read_message(s)
        global other_user_cert
        other_user_cert = load_certificate(certificate)
        # create the new socket for exchanging messages
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_chat:
            s_chat.bind((new_host, int(new_port)))
            s_chat.listen()
            self.add_message(f'{USERNAME} has joined the chat!')
            other_user, ip = s_chat.accept()
            threadRecv = threading.Thread(target=self.recv, args=(
                    other_user, OTHER_USERNAME,)).start()
            while True :
                self.socket = other_user
                other_user.sendall(encrypt_message(input('->'),other_user_cert))
    def accept_communication(self ,s: socket):
        data = bytearray()
        data.extend(USERNAME.encode('utf-8') + DELIMETER)
        data.extend(OTHER_USERNAME.encode("utf-8"))
        s.sendall(bytes(data))
        data = read_message(s)
        global other_user_cert
        self.host, self.port, other_user_cert = data.split(DELIMETER)
        self.host = self.host.decode("utf-8")
        self.port = int(self.port.decode("utf-8"))
        other_user_cert = load_certificate(other_user_cert)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s_chat:
            self.add_message(f'{USERNAME} has joined the chat!')
            s_chat.connect((self.host, self.port))
            other_threadRecv = threading.Thread(
                    target=self.recv, args=(s_chat,OTHER_USERNAME,)).start()
            while True :
                self.socket = s_chat
                s_chat.sendall(encrypt_message(input('->'),other_user_cert))

    def send_message(self) :
        message = self.message_textbox.get()
        self.add_message(f'[{USERNAME}]: {message}')
        self.message_textbox.delete(0, len(message))
        message = encrypt_message(message,other_user_cert)
        self.socket.sendall(message)

    def handleConnection(self , username):
        global OTHER_USERNAME 
        OTHER_USERNAME = username
        host = "127.0.0.1"
        port = 65433
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            if ROLE == "1":
                send_option(s, b"OP_INIT_COMM")
                self.initiate_communication(s)
            elif ROLE == "2":
                send_option(s, b"OP_ACC_COMM")
                self.accept_communication(s)
            else:
                print("Option not supported!")
if __name__ == "__main__":
    # request_certificate()
    # certificate = load_certificate("../ca/mfdutra.crt")
    # cipher = encrypt_message("degla fsfs", certificate=certificate)
    # msg = decrypt_message(cipher)
    # print(msg)
    global ROLE
    ROLE = sys.argv[1]
    gui = GUI()
 

