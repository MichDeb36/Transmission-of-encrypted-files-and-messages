from tkinter.filedialog import askopenfilename
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from tkinter import messagebox
import time
import socket
import threading
import os

class FileTransfer():
    def __init__(self, user, ip):
        self.BUFFER_SIZE_FILE = 8388608
        self.BUFFER_SIZE_KEY = 10000
        self.IP = ip
        self.session_key = get_random_bytes(32)
        self.file_to_encrypt = ""
        self.SEPARATOR = "<SEPARATOR>"
        self.PORT = 5000
        self.SIGN_ECB = "1"
        self.SIGN_CBC = "2"
        self.SIGN_CFB = "3"
        self.SIGN_OFB = "4"
        if (user == '1'):
            threadServer = threading.Thread(target=self.server)
            threadServer.start()
        elif (user == '2'):
            threadServer = threading.Thread(target=self.client)
            threadServer.start()

    def choiseFill(self):
        filename = askopenfilename()
        self.file_to_encrypt = filename

    def setFile_to_encrypt(self, name):
        self.file_to_encrypt = name

    def getFile_to_encrypt(self):
        return self.file_to_encrypt

    def generateSession_key(self):
        session_key = get_random_bytes(32)
        return session_key

    def getSession_key(self):
        return self.session_key

    def setSession_key(self, session_key):
        self.session_key = session_key


    def encrypt_RSA(self, session_key):
        f = open('Received_files\public.pem', 'r')
        publicKey = RSA.import_key(f.read())
        encryptor = PKCS1_OAEP.new(publicKey)
        encrypted_session_key = encryptor.encrypt(session_key)
        return encrypted_session_key

    def dencrypt_RSA(self, encrypted_session_key):
        f = open('Keys\Private\private.pem', 'r')
        privateKey = RSA.import_key(f.read())
        decryptor = PKCS1_OAEP.new(privateKey)
        session_key = decryptor.decrypt(encrypted_session_key)
        return session_key

    def sendFile(self, filename, user):
        file_size = os.path.getsize(filename)
        if (user == '1'):
            self.server_file.send(f"{filename}{self.SEPARATOR}{file_size}".encode())
        elif (user == '2'):
            self.client_socket.send(f"{filename}{self.SEPARATOR}{file_size}".encode())
        print("Start uploaded")
        with open(filename, "rb") as f:
            for _ in range(file_size):
                bytes_read = f.read(self.BUFFER_SIZE_FILE)
                if not bytes_read:
                    print("Uploaded file")
                    filename = os.path.basename(filename)
                    messagebox.showinfo("Uploading file", "Uploaded file: "+filename[0:-1])
                    break
                if (user == '1'):
                    self.server_file.sendall(bytes_read)
                elif (user == '2'):
                    self.client_socket.sendall(bytes_read)

    def server(self):
        print("Create server")
        server_socket = socket.socket()
        server_socket.bind((self.IP, self.PORT))
        server_socket.listen(1)
        self.server_file, address = server_socket.accept()
        print("Connected with: " + str(address))

        with open('Keys\Public\public.pem', "rb") as f:
            bytes_read = f.read(self.BUFFER_SIZE_KEY)
            self.server_file.sendall(bytes_read)
        print('Sent public key')
        encrypted_session_key = self.server_file.recv(1024)
        session_key = self.dencrypt_RSA(encrypted_session_key)
        self.setSession_key(session_key)
        while True:
            data = self.server_file.recv(self.BUFFER_SIZE_FILE).decode()
            file_name, file_size = data.split(self.SEPARATOR)
            file_name = os.path.basename(file_name)
            file_size = int(file_size)
            self.setFile_to_encrypt(file_name)
            print('Starting the download')
            counter = file_size
            with open("Received_files\\For_decryption\\" + file_name, "wb") as f:
                for _ in range(file_size):
                    bytes_read = self.server_file.recv(self.BUFFER_SIZE_FILE)
                    counter = counter - self.BUFFER_SIZE_FILE
                    f.write(bytes_read)
                    if counter <= 0:
                        print("File received, start decryption")
                        self.choiseDecrypt()
                        break
            if not data:
                break
        self.server_file.close()
        server_socket.close()


    def client(self):
        self.client_socket = socket.socket()
        self.client_socket.connect((self.IP, self.PORT))

        with open('Received_files\public.pem', "wb") as f:
            bytes_read = self.client_socket.recv(self.BUFFER_SIZE_KEY)
            f.write(bytes_read)
        print('Public key received')
        session_key = self.getSession_key()
        encrypted_session_key = self.encrypt_RSA(session_key)
        self.client_socket.send(encrypted_session_key)
        print("Sent encrypted session key")
        while True:
            data = self.client_socket.recv(self.BUFFER_SIZE_FILE).decode()
            file_name, file_size = data.split(self.SEPARATOR)
            file_name = os.path.basename(file_name)
            file_size = int(file_size)
            self.setFile_to_encrypt(file_name)
            counter = file_size
            print('Starting the download')
            with open("Received_files\\For_decryption\\" + file_name, "wb") as f:
                for _ in range(file_size):
                    bytes_read = self.client_socket.recv(self.BUFFER_SIZE_FILE)
                    counter = counter - self.BUFFER_SIZE_FILE
                    f.write(bytes_read)
                    if counter <= 0:
                        print("Received file, start decryption")
                        self.choiseDecrypt()
                        break
            if not data:
                break
        self.client_socket.close()

    def choiseEncrypt(self, progress, root, selectButton, user):
        if selectButton.get() == "1":
            self.encryptECB(progress, root, user)
        elif selectButton.get() == "2":
            self.encryptCBC(progress, root, user)
        elif selectButton.get() == "3":
            self.encryptCFB(progress, root, user)
        elif selectButton.get() == "4":
            self.encryptOFB(progress, root, user)

    def choiseDecrypt(self):
        filname = self.getFile_to_encrypt()
        char = filname[-1]
        key = self.getSession_key()
        file_to_decrypt = self.getFile_to_encrypt()
        input_file = open("Received_files\\For_decryption\\" + file_to_decrypt, 'rb')
        file_to_decrypt = file_to_decrypt[0:-1]
        output_file = open("Received_files\\" + file_to_decrypt, 'wb')
        if char == "1":
            out = input_file.read(16)
            cipher_encrypt = AES.new(key, AES.MODE_ECB)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

            while len(buffer) > 0:
                decrypted_bytes = cipher_encrypt.decrypt(buffer)
                output_file.write(decrypted_bytes)
                out = input_file.read(16)
                buffer = input_file.read(self.BUFFER_SIZE_FILE)
            print("End of decryption ECB")

        elif char == "4":
            iv = input_file.read(16)
            cipher_encrypt = AES.new(key, AES.MODE_OFB, iv=iv)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

            while len(buffer) > 0:
                decrypted_bytes = cipher_encrypt.decrypt(buffer)
                output_file.write(decrypted_bytes)
                buffer = input_file.read(self.BUFFER_SIZE_FILE)
            print("End of decryption OFB")

        elif char == "2":
            cipher_encrypt = AES.new(key, AES.MODE_CBC)
            output_file.write(cipher_encrypt.iv)

            buffer = input_file.read(self.BUFFER_SIZE_FILE)
            while len(buffer) > 0:
                ciphered_bytes = cipher_encrypt.encrypt(pad(buffer, AES.block_size))
                output_file.write(ciphered_bytes)
                buffer = input_file.read(self.BUFFER_SIZE_FILE)
            print("End of decryption CBC")

        elif char == "3":
            iv = input_file.read(16)
            cipher_encrypt = AES.new(key, AES.MODE_CFB, iv=iv)

            buffer = input_file.read(self.BUFFER_SIZE_FILE)
            while len(buffer) > 0:
                decrypted_bytes = cipher_encrypt.decrypt(buffer)
                output_file.write(decrypted_bytes)
                buffer = input_file.read(self.BUFFER_SIZE_FILE)
            print("End of decryption CFB")

        input_file.close()
        output_file.close()
        messagebox.showinfo("Received file ", "Received file is: " + file_to_decrypt)


    def encryptCFB(self, progress, root, user):
        time_start = time.time()
        file_to_encrypt = self.getFile_to_encrypt()
        size = os.stat(file_to_encrypt).st_size
        step = 100/(size/self.BUFFER_SIZE_FILE)
        print("Encryption CFB")
        key = self.getSession_key()

        input_file = open(file_to_encrypt, 'rb')
        self.setFile_to_encrypt(os.path.basename(file_to_encrypt))
        file_to_encrypt = self.getFile_to_encrypt()
        output_file = open("Encrypted\\" + file_to_encrypt+self.SIGN_CFB, 'wb')

        cipher_encrypt = AES.new(key, AES.MODE_CFB)
        output_file.write(cipher_encrypt.iv)

        buffer = input_file.read(self.BUFFER_SIZE_FILE)
        counter = step
        while len(buffer) > 0:
            counter = counter + step
            progress['value'] = counter
            root.update_idletasks()
            ciphered_bytes = cipher_encrypt.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

        progress['value'] = 100
        input_file.close()
        output_file.close()
        print("End CFB")
        time_finish = time.time() - time_start
        print("Time CFB: " + str(time_finish))
        self.sendFile("Encrypted\\" + file_to_encrypt+self.SIGN_CFB, user)

    def encryptCBC(self, progress, root,user):
        time_start = time.time()
        file_to_encrypt = self.getFile_to_encrypt()
        size = os.stat(file_to_encrypt).st_size
        step = 100 / (size / self.BUFFER_SIZE_FILE)
        print("Encryption CBC")
        key = self.getSession_key()

        input_file = open(file_to_encrypt, 'rb')
        file_to_encrypt = os.path.basename(file_to_encrypt)
        output_file = open("Encrypted\\" + file_to_encrypt+self.SIGN_CBC, 'wb')

        cipher_encrypt = AES.new(key, AES.MODE_CBC)
        output_file.write(cipher_encrypt.iv)

        buffer = input_file.read(self.BUFFER_SIZE_FILE)
        counter = step
        while len(buffer) > 0:
            counter = counter + step
            progress['value'] = counter
            root.update_idletasks()
            ciphered_bytes = cipher_encrypt.encrypt(pad(buffer, AES.block_size))
            output_file.write(ciphered_bytes)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

        progress['value'] = 100
        input_file.close()
        output_file.close()
        print("End CBC")
        time_finish = time.time() - time_start
        print("Time CBC: " + str(time_finish))
        self.sendFile("Encrypted\\" + file_to_encrypt+self.SIGN_CBC, user)


    def encryptOFB(self, progress, root, user):
        time_start = time.time()
        file_to_encrypt = self.getFile_to_encrypt()
        size = os.stat(file_to_encrypt).st_size
        step = 100 / (size / self.BUFFER_SIZE_FILE)
        print("Encryption OFB")
        key = self.getSession_key()
        input_file = open(file_to_encrypt, 'rb')
        file_to_encrypt = os.path.basename(self.file_to_encrypt)
        output_file = open("Encrypted\\" + file_to_encrypt+self.SIGN_OFB, 'wb')

        cipher_encrypt = AES.new(key, AES.MODE_OFB)
        output_file.write(cipher_encrypt.iv)

        buffer = input_file.read(self.BUFFER_SIZE_FILE)
        counter = step
        while len(buffer) > 0:
            counter = counter + step
            progress['value'] = counter
            root.update_idletasks()
            ciphered_bytes = cipher_encrypt.encrypt(buffer)
            output_file.write(ciphered_bytes)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

        progress['value'] = 100
        input_file.close()
        output_file.close()
        print("End OFB")
        time_finish = time.time() - time_start
        print("Time OFB: " + str(time_finish))
        self.sendFile("Encrypted\\" + file_to_encrypt+self.SIGN_OFB, user)


    def encryptECB(self, progress, root,user):
        time_start = time.time()
        file_to_encrypt = self.getFile_to_encrypt()
        size = os.stat(file_to_encrypt).st_size
        step = 100 / (size / self.BUFFER_SIZE_FILE)
        print("Encryption ECB")
        key = self.getSession_key()

        input_file = open(file_to_encrypt, 'rb')
        file_to_encrypt = os.path.basename(file_to_encrypt)
        output_file = open("Encrypted\\" + file_to_encrypt+self.SIGN_ECB, 'wb')

        cipher_encrypt = AES.new(key, AES.MODE_ECB)

        buffer = input_file.read(self.BUFFER_SIZE_FILE)
        counter = step
        while len(buffer) > 0:
            counter = counter + step
            progress['value'] = counter
            root.update_idletasks()
            ciphered_bytes = cipher_encrypt.encrypt(pad(buffer, AES.block_size))
            output_file.write(ciphered_bytes)
            buffer = input_file.read(self.BUFFER_SIZE_FILE)

        progress['value'] = 100
        input_file.close()
        output_file.close()
        print("End ECB")
        timefinish = time.time() - time_start
        print("Time ECB: " + str(timefinish))
        self.sendFile("Encrypted\\" + file_to_encrypt+self.SIGN_ECB, user)











