import socket
import pickle
import sys
import threading
import secrets
import string
import random
import os
import hashlib
from datetime import datetime, timedelta
from Send_Email import send_Email_Verification

from tcp_by_size import recv_by_size, send_with_size
import AES_ENCRYPTION
import RSA_ENCRYPTION
from Crypto.PublicKey import RSA

DICT_USERS = {}
pkl_file_lock = threading.Lock()

VERIFICATION_USERS = {}
verification_users_lock = threading.Lock()
PUBLIC_KEY_PATH = "TRACKER_RSA_KEYS\\public_key.pem"
PRIVATE_KEY_PATH = "TRACKER_RSA_KEYS\\private_key.pem"
RSA_PRIVATE_KEY, RSA_PUBLIC_KEY = RSA_ENCRYPTION.Generate_And_Save_Rsa_Keys_In_Disk_PEM(PUBLIC_KEY_PATH,

                                                                                        PRIVATE_KEY_PATH)
def is_valid_aes_key(key: bytes) -> bool:
    return isinstance(key, bytes) and len(key) in {16, 24, 32}

def handle_client(sock: socket, adr):
    global DICT_USERS
    global pkl_file_lock
    global VERIFICATION_USERS
    global PUBLIC_KEY_PATH
    global PRIVATE_KEY_PATH
    global RSA_PRIVATE_KEY
    global RSA_PUBLIC_KEY
    SUCCESS = False
    DICT_USERS = Get_Dict_Users("users.pkl")
    print("dict users ---> ")
    print(DICT_USERS)

    # send RSA public key
    pem_format_rsa_public_key = RSA_PUBLIC_KEY.export_key()
    send_with_size(sock, pem_format_rsa_public_key)
    recvd_mes = recv_by_size(sock)
    if recvd_mes != b"SUCCESS":
        print("rsa bad format")
        sys.exit(0)

    AES_Session_Key_encrypted = recv_by_size(sock)
    print(AES_Session_Key_encrypted)
    AES_Session_Key = RSA_ENCRYPTION.rsa_decrypt(AES_Session_Key_encrypted, RSA_PRIVATE_KEY)
    if not is_valid_aes_key(AES_Session_Key):
        mes = b"ERR~2"
        send_with_size(sock,mes)
        print("aes session key not valid aes session key : ")
        print(AES_Session_Key)
        sys.exit(0)
    else:
        send_with_size(sock,b"SUCCESS")
    print(AES_Session_Key)


    while not SUCCESS:
        enc_bdata = recv_by_size(sock)
        if enc_bdata == b"":
            break
        bdata = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_bdata, AES_Session_Key)
        action = extarct_action(bdata)
        input_user_name = GetUserName(bdata)
        input_password = GetPassword(bdata)

        if action == "CHG_PASS":
            verification_code = Generate_Verification_Code()
            expire_time = datetime.now() + timedelta(minutes=10)
            user_verify = {"VERIFY_CODE": verification_code, "EXPIRE_TIME": expire_time}
            print(verification_code)
            verification_users_lock.acquire()
            VERIFICATION_USERS[input_user_name] = user_verify
            verification_users_lock.release()
            send_Email_Verification("erezlahav10@gmail.com", input_user_name, verification_code)

            is_verifed = recv_verification(sock, AES_Session_Key, expire_time, verification_code)

            print(is_verifed)
            enc_recved_data = recv_by_size(sock)
            recved_data = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_recved_data, AES_Session_Key)
            command = extarct_action(recved_data)
            email = GetUserName(recved_data)
            password = GetPassword(recved_data)
            Change_User_Pass(email, password)
            d = Get_Dict_Users("users.pkl")
            print("new dict---->")
            print(d)
            mes = b"suc"
            enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
            send_with_size(sock, enc_mes)

        if action == "LOGIN":
            if input_user_name not in DICT_USERS.keys():
                mes = b"error"
                enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                send_with_size(sock, enc_mes)
                print("error 1")

            elif DICT_USERS.get(input_user_name) is None:
                mes = b"error"
                enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                send_with_size(sock, enc_mes)
                print("error 2")

            else:
                pass_salt_dic = DICT_USERS.get(input_user_name)
                password_from_dic, salt = Get_Pass_Salt_From_Dic(pass_salt_dic)
                print(password_from_dic)

                hashed_salted_input_pass = hash_and_salt_pass(input_password, salt)
                print(hashed_salted_input_pass)
                if password_from_dic == hashed_salted_input_pass:
                    SUCCESS = True
                    print("success")
                    mes = b"success"
                    enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                    send_with_size(sock, enc_mes)
                else:
                    print("error 3")
                    mes = b"error"
                    enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                    send_with_size(sock, enc_mes)


        elif action == "SIGNUP":
            if input_user_name in DICT_USERS.keys() or input_user_name in VERIFICATION_USERS.keys():  #username already taken
                mes = b"error"
                enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                send_with_size(sock, enc_mes)
                print("error")
            else:
                SUCCESS = True
                mes = b"success"
                enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
                send_with_size(sock, enc_mes)

                verification_code = Generate_Verification_Code()
                expire_time = datetime.now() + timedelta(minutes=10)
                print(verification_code)
                user_verify = {"VERIFY_CODE": verification_code, "EXPIRE_TIME": expire_time}
                print(user_verify)

                verification_users_lock.acquire()
                VERIFICATION_USERS[input_user_name] = user_verify
                verification_users_lock.release()
                print(VERIFICATION_USERS)
                send_Email_Verification("erezlahav10@gmail.com", input_user_name, verification_code)

                is_verifed = recv_verification(sock, AES_Session_Key, expire_time, verification_code)
                print(is_verifed)
                if is_verifed:
                    Add_User(input_user_name, input_password)


def Generate_Verification_Code(length=6):
    characters = string.ascii_letters + string.digits  # A-Z, a-z, 0-9
    return ''.join(random.choices(characters, k=length))


def recv_verification(sock: socket, AES_Session_Key, expired_date: datetime, verification_code) -> bool:
    enc_recv_code = recv_by_size(sock)
    recv_code = AES_ENCRYPTION.Decrypt_AES_CBC_CipherText(enc_recv_code, AES_Session_Key).decode()
    print(recv_code)
    recved_time = datetime.now()
    if not (expired_date - recved_time <= timedelta(minutes=10)):
        print("time is over")
        return False
    code = recv_code.split("#")[1]
    if code == verification_code:
        print("success verify")
        mes = b"SUC_VER"
        enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
        send_with_size(sock, enc_mes)
        return True
    else:
        print("code false")
        mes = b"ERR_VER"
        enc_mes = AES_ENCRYPTION.Encrypt_AES_CBC_PlainText(mes, AES_Session_Key)
        send_with_size(sock, enc_mes)
        return False


def Generate_Salt():
    salt = secrets.token_hex(16)
    print(salt)
    return salt


def Get_Pass_Salt_From_Dic(pass_salt_dic: dict) -> tuple:
    password = pass_salt_dic.get("password")
    salt = pass_salt_dic.get("salt")
    return password, salt


def hash_and_salt_pass(password, salt):
    hashed_salted_pass = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex()
    print(hashed_salted_pass)
    return hashed_salted_pass


def GetUserName(bdada: bytes) -> str:
    try:
        return bdada.split(b"~")[1].decode()
    except Exception as e:
        return "None"


def GetPassword(bdada: bytes) -> str:
    try:
        return bdada.split(b"~")[2].decode()
    except Exception as e:
        return "None"


def Get_Dict_Users(pickle_file_name) -> dict:
    dic_to_return = {}
    try:
        with open(pickle_file_name, "rb") as pickle_users:
            users_str = pickle.load(pickle_users)
            lines = users_str.split("\n")

        for line in lines:
            vals = line.split(":")
            user_name = vals[0]
            password = vals[1]
            salt = vals[2]
            dict_pass_salt = {"password": password, "salt": salt}
            dic_to_return[user_name] = dict_pass_salt




    except Exception as e:
        print(e)
        dic_to_return[" "] = " "

    return dic_to_return


def GetPickleLines(pickle_file):
    with open(pickle_file, 'rb') as pickle_file:
        users_str = pickle.load(pickle_file)
        lines = users_str.split("\n")

    return lines


def Change_User_Pass(username, new_password):
    global pkl_file_lock
    with open("users.pkl", "rb") as users_file:
        users_data = pickle.load(users_file)
        lines = users_data.split("\n")

    updated_lines = []
    for line in lines:
        if not (line.startswith(username)):
            updated_lines.append(line)
        else:
            salt = Generate_Salt()
            password_to_put = hash_and_salt_pass(new_password, salt)
            new_line = username + ":" + password_to_put + ":" + salt
            updated_lines.append(new_line)

    data_to_load_pkl_file = "\n".join(updated_lines) + "\n"

    pkl_file_lock.acquire()
    with open("users.pkl", "wb") as users:
        pickle.dump(data_to_load_pkl_file, users)
    pkl_file_lock.release()


def Add_User(user_name, password):
    global pkl_file_lock

    try:
        with open("users.pkl", "rb") as users_file:
            users_data = pickle.load(users_file)
    except Exception as e:
        print(e)
        users_data = ""

    salt = Generate_Salt()
    password_to_put = hash_and_salt_pass(password, salt)
    line_to_add = user_name + ":" + password_to_put + ":" + salt
    users_data += line_to_add + "\n"

    pkl_file_lock.acquire()
    with open("users.pkl", "wb") as users_file:
        pickle.dump(users_data, users_file)

    pkl_file_lock.release()


def IsGoodDict(dic: dict):
    if dic[" "] == " ":
        return False

    return True


def extarct_action(bdata: bytes):
    return bdata.split(b"~")[0].decode()
