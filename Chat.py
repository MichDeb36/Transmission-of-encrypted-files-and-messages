from tkinter import messagebox
from Crypto.Random import get_random_bytes
from base64 import b64encode,b64decode
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import *
from Crypto.Util.Padding import pad
import json
import socket
import threading

class Chat():
    def __init__(self, user, chat, ip, password):
        self.IP = ip
        self.PORT = 5000
        self.chat = chat
        self.BUFFER_SIZE_KEY = 10000
        self.BUFFER_SIZE_MESSAGE =1024
        self.SERVER_USER = '1'
        self.CLIENT_USER = '2'
        self.CLIENTS = 1
        self.PASSWORD = password
        self.signal_exit = False
        if(user == self.SERVER_USER):
            self.threadServer = threading.Thread(target=self.server)
            self.threadServer.start()
        elif(user == self.CLIENT_USER):
            threadClient = threading.Thread(target=self.client)
            threadClient.start()

    def generateRSA(self):
        session_key = get_random_bytes(32)
        return session_key

    def encrypt_RSA(self, session_key):
        f = open('Received_files\public.pem', 'r')
        public_key = RSA.import_key(f.read())
        encryptor = PKCS1_OAEP.new(public_key)
        encrypted_session_key = encryptor.encrypt(session_key)
        return encrypted_session_key

    def dencrypt_RSA(self, encrypted_session_key):
        f = open('Keys\Private\private.pem', 'r')
        private_key = RSA.import_key(f.read())
        decryptor = PKCS1_OAEP.new(private_key)
        session_key = decryptor.decrypt(encrypted_session_key)
        return session_key

    def encrypt_AES_CFB(self, session_key, message):
        cipher_encrypt = AES.new(session_key, AES.MODE_OFB)
        encrypt_bytes = cipher_encrypt.encrypt(message)
        iv = b64encode(cipher_encrypt.iv).decode('utf-8')
        text = b64encode(encrypt_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'encrypttext': text})
        return result

    def decrypte_AES_CFB(self, session_key, encryptMessage):
        b64 = json.loads(encryptMessage)
        iv = b64decode(b64['iv'])
        encrypt_text = b64decode(b64['encrypttext'])
        cipher = AES.new(session_key, AES.MODE_OFB, iv=iv)
        message = cipher.decrypt(encrypt_text)
        return message


    def server(self):
        server_socket = socket.socket()
        server_socket.bind((self.IP, self.PORT))
        print("Create Server")
        server_socket.listen(self.CLIENTS)
        self.server_message, address = server_socket.accept()
        print("Connected with: " + str(address))
        self.saveMessage("Connected with the client", "System:")

        with open('Keys\Public\public.pem', "rb") as f:
            bytes_read = f.read(self.BUFFER_SIZE_KEY)
            self.server_message.sendall(bytes_read)
        print('Sent public key')
        encrypted_session_key = self.server_message.recv(self.BUFFER_SIZE_MESSAGE)
        self.session_key = self.dencrypt_RSA(encrypted_session_key)

        while True:
            data = self.server_message.recv(self.BUFFER_SIZE_MESSAGE).decode()
            if self.signal_exit:
                print("Sygnal server")
                break
            message = self.decrypte_AES_CFB(self.session_key, data)
            self.saveMessage(message, "User_client:")
        self.server_message.close()

    def client(self):
        self.client_socket = socket.socket()
        self.client_socket.connect((self.IP, self.PORT))
        self.saveMessage("Connected with the server", "System:")
        with open('Received_files\public.pem', "wb") as f:
            bytes_read = self.client_socket.recv(self.BUFFER_SIZE_KEY)
            f.write(bytes_read)
        print('Public key received')
        self.session_key = self.generateRSA()
        encrypted_session_key = self.encrypt_RSA(self.session_key)
        self.client_socket.send(encrypted_session_key)
        print("Sent encrypted session key")
        while True:
            data = self.client_socket.recv(self.BUFFER_SIZE_MESSAGE).decode()  #
            if self.signal_exit:
                print("Sygnal client")
                break
            message = self.decrypte_AES_CFB(self.session_key, data)
            self.saveMessage(message, "User_server:")
        self.client_socket.close()

    def sendMessage(self, message, user):
        if (user == self.SERVER_USER):
            encryptMessage = self.encrypt_AES_CFB(self.session_key, message.get().encode())
            self.server_message.send(encryptMessage.encode())
            self.saveMessage(message.get(), "User_server:")
        elif(user == self.CLIENT_USER):
            encryptMessage = self.encrypt_AES_CFB(self.session_key, message.get().encode())
            self.client_socket.send(encryptMessage.encode())
            self.saveMessage(message.get(), "User_client:")
        message.delete(0, END)

    def saveMessage(self, text, name):
        self.chat.insert(END, '\n')
        self.chat.insert(END, name)
        self.chat.insert(END, '\n')
        self.chat.insert(END, text)

