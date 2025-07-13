import socket
import sys
import threading
import tkinter as tk
from tkinter import ttk

from Crypto.PublicKey import RSA
from tcp_by_size import send_with_size, recv_by_size
import AES_ENCRYPTION
import RSA_ENCRYPTION

LOGGED_IN = False
LOGGED_LOCK = threading.Lock()
VERIFIED = False
VER_LOCK = threading.Lock()
Aes_session_key = AES_ENCRYPTION.Generate_AES_CBC_256_Bit_Key()
USER_NAME = ""


def is_valid_rsa_public_key(key_data: bytes) -> bool:
    try:
        key = RSA.import_key(key_data)
        return key.has_private() is False  # Make sure it's public, not private
    except Exception as e:
        print(e)
        return False


def start_client(sock: socket) -> str:
    global LOGGED_IN
    global Aes_session_key
    global USER_NAME
    print(Aes_session_key)
    server_rsa_public_key_pem_format = recv_by_size(sock)
    if not is_valid_rsa_public_key(server_rsa_public_key_pem_format):
        mes = b"ERR~1"
        send_with_size(sock, mes)
        print("invalid rsa public key format recved")
        sys.exit()
    else:
        send_with_size(sock,b"SUCCESS")

    server_rsa_public_key = RSA.import_key(server_rsa_public_key_pem_format)
    message = Aes_session_key
    cipher_aes_session_key = RSA_ENCRYPTION.rsa_encrypt(message, server_rsa_public_key)
    print(cipher_aes_session_key)
    send_with_size(sock, cipher_aes_session_key)
    recvd_mes = recv_by_size(sock)
    if recvd_mes != b"SUCCESS":
        print("aes session key bad format")
        sys.exit()

    t_login = threading.Thread(target=SIGNTOAPP, args=(sock,))
    t_login.start()
    while True:
        LOGGED_LOCK.acquire()
        if LOGGED_IN:
            LOGGED_LOCK.release()
            break
        LOGGED_LOCK.release()

    print("Logged in!!")
    return USER_NAME


def SIGNTOAPP(sock: socket):
    root = start_window(sock)
    root.mainloop()


def Verify_Email(sock: socket, da_root, change_password=False, email=None):
    global Aes_session_key
    if change_password and email is not None:
        data_to_send = b"CHG_PASS~" + email.encode()
        enc_data_to_send = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(data_to_send, Aes_session_key)
        send_with_size(sock, enc_data_to_send)
    da_root.destroy()
    da_root = tk.Tk()
    da_root.title("Verification Email")
    da_root.geometry("300x150")
    da_root.resizable(False, False)  # Disable window resizing

    tk.Label(da_root, text="Enter Code: ").pack()
    input_code = tk.Entry(da_root, width=30)
    input_code.pack()

    verify_button = tk.Button(da_root, text="Send", command=lambda: send_code(sock, input_code.get(), da_root))
    verify_button.pack()

    da_root.mainloop()
    enc_bdata = recv_by_size(sock)
    bdata = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_bdata, Aes_session_key)
    print(bdata)
    if change_password and email is not None:
        if bdata == b"SUC_VER":
            Change_Password(sock, da_root, email)
    return bdata == b"SUC_VER"


def send_code(sock: socket, code, da_root):
    global Aes_session_key
    print(code)
    mes = b"VER#" + str(code).encode()
    enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, Aes_session_key)
    send_with_size(sock, enc_mes)
    da_root.destroy()


def signup(sock, root, email, password, very_password):
    global LOGGED_IN
    global Aes_session_key
    global USER_NAME
    email = email.get()
    password = password.get()
    very_password = very_password.get()
    if password != very_password:
        signup_action(sock, root)
    else:
        mes_to_send = b"SIGNUP~" + email.encode() + b"~" + password.encode()
        enc_mes_to_send = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes_to_send, Aes_session_key)
        send_with_size(sock, enc_mes_to_send)

        enc_data_rcv = recv_by_size(sock)
        data_rcv = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_data_rcv, Aes_session_key).decode()
        print(data_rcv)
        if data_rcv != "success":
            print("error try again")
            signup_action(sock, root)
        else:
            print("success!!!")
            print("Calling Verify_Email now...")
            is_success = Verify_Email(sock, root)
            print(is_success)
            print(f"Verify_Email returned: {is_success}")
            if is_success:
                LOGGED_LOCK.acquire()
                LOGGED_IN = True
                USER_NAME = email
                LOGGED_LOCK.release()

            root.quit()


def login(sock: socket, root, entry_user_name, entry_password):
    global LOGGED_IN
    global Aes_session_key
    global USER_NAME
    user_name = entry_user_name.get()
    password = entry_password.get()
    print(f"Username: {user_name}, Password: {password}")
    mes_to_send = b"LOGIN~" + user_name.encode() + b"~" + password.encode()
    enc_mes_to_send = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes_to_send, Aes_session_key)
    send_with_size(sock, enc_mes_to_send)
    enc_data_rcv = recv_by_size(sock)
    data_rcv = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_data_rcv, Aes_session_key).decode()
    print(data_rcv)
    if data_rcv != "success":
        print("error in login try again")
        login_action(sock, root)
    else:
        print("success!!")
        LOGGED_LOCK.acquire()
        LOGGED_IN = True
        USER_NAME = user_name
        LOGGED_LOCK.release()
        root.destroy()


def login_action(sock: socket, root):
    root.destroy()

    root = tk.Tk()
    root.title("LOG In")
    root.geometry("300x150")
    root.resizable(False, False)  # Disable window resizing

    tk.Label(root, text="Email: ").pack()
    email_entry = tk.Entry(root, width=30)
    email_entry.pack()

    tk.Label(root, text="Password: ").pack()
    password_entry = tk.Entry(root, width=30, show="*")
    password_entry.pack()

    forgot_password_button = tk.Button(root, text="Forgot password", command=lambda: ForgotPassword(sock, root))
    forgot_password_button.pack()

    login_button = tk.Button(root, text="LOGIN", command=lambda: login(sock, root, email_entry, password_entry))
    login_button.pack()


def ForgotPassword(sock: socket, root):
    root.destroy()

    root = tk.Tk()
    root.title("Forgot Password")
    root.geometry("300x150")
    root.resizable(False, False)  # Disable window resizing

    tk.Label(root, text="Email: ").pack()
    email_entry = tk.Entry(root, width=30)
    email_entry.pack()

    Verify = tk.Button(root, text="Verify Email",
                       command=lambda: Verify_Email(sock, root, change_password=True, email=email_entry.get()))
    Verify.pack()


def Change_Password(sock: socket, root, email):
    root = tk.Tk()
    root.title("Change Password")
    root.geometry("300x150")
    root.resizable(False, False)  # Disable window resizing

    tk.Label(root, text="Password: ").pack()
    password_entry = tk.Entry(root, width=30, show="*")
    password_entry.pack()

    tk.Label(root, text="Verification Password: ").pack()
    very_password = tk.Entry(root, width=30, show="*")
    very_password.pack()

    Change_Password = tk.Button(root, text="Change Password", command=lambda: Send_Changed_Password(sock, root, email,
                                                                                                    password_entry.get(),
                                                                                                    very_password.get()))
    Change_Password.pack()


def Send_Changed_Password(sock: socket, root, email, password, veri_password):
    global Aes_session_key
    if password != veri_password:
        Change_Password(sock, root, email)
    else:
        mes_to_send = b"RE_LOG~" + email.encode() + b"~" + password.encode()
        enc_mes_to_send = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes_to_send, Aes_session_key)

        send_with_size(sock, enc_mes_to_send)

        enc_bdata = recv_by_size(sock)
        bdata = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_bdata, Aes_session_key)
        print(bdata)
        root.destroy()


def signup_action(sock: socket, root):
    root.destroy()

    root = tk.Tk()
    root.title("Sign UP")
    root.geometry("300x150")
    root.resizable(False, False)  # Disable window resizing

    tk.Label(root, text="Email: ").pack()
    email_entry = tk.Entry(root, width=30)
    email_entry.pack()

    tk.Label(root, text="Password: ").pack()
    password_entry = tk.Entry(root, width=30, show="*")
    password_entry.pack()

    tk.Label(root, text="Verification Password: ").pack()
    very_password = tk.Entry(root, width=30, show="*")
    very_password.pack()

    login_button = tk.Button(root, text="SIGN UP",
                             command=lambda: signup(sock, root, email_entry, password_entry, very_password))
    login_button.pack()


def start_window(sock: socket):
    root = tk.Tk()
    root.title("Sign In")
    root.geometry("300x150")
    root.resizable(False, False)  # Disable window resizing

    tk.Button(root, text="Login", width=20, height=2, pady=20, command=lambda: login_action(sock, root)).pack()
    tk.Button(root, text="Sign Up", width=20, height=2, pady=20, command=lambda: signup_action(sock, root)).pack()
    # Login Button
    return root
