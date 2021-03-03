from tkinter import messagebox
from tkinter.ttk import *
from Chat import *
from Files import *
from hashlib import sha256

class Gui():
    def __init__(self):
        self.window = Tk()
        self.window.title("Transfer")
        self.window.configure(bg='#A9A9A9')
        info_IP = Label(self.window, text="IP:", width=20)
        info_password = Label(self.window, text="Password:", width=20)
        IP = Entry(self.window,  text="User1", width=20)
        password = Entry(self.window, show="*", width=20)
        info_select_server_client = Label(self.window, text="User type")
        select_button_SC = StringVar()
        server = Radiobutton(self.window, variable=select_button_SC, value="1", text="Server")
        client = Radiobutton(self.window, variable=select_button_SC, value="2", text="Client")
        select_button_SC.set("1")
        ok = Button(self.window, text="OK", width=20, command=lambda: self.checkPassword(password.get(), select_button_SC.get(), IP.get()))
        exit = Button(self.window, text="Exit", width=20, command=self.exit)
        padx = 3
        pady = 5
        info_IP.grid(row=0, column=0, padx=padx, pady=pady)
        IP.grid(row=0, column=1,  padx=padx, pady=pady)
        info_password.grid(row=1, column=0,  padx=padx, pady=pady)
        password.grid(row=1, column=1,  padx=padx, pady=pady)
        info_select_server_client.grid(row=2, column=0, columnspan=2, padx=padx, pady=pady)
        server.grid(row=3, column=0, padx=padx, pady=pady)
        client.grid(row=3, column=1, padx=padx, pady=pady)
        ok.grid(row=4, column=0, padx=padx, pady=pady)
        exit.grid(row=4, column=1,  padx=padx, pady=pady)
        mainloop()

    def checkPassword(self, password, selectButton, IP):
        hashPassword = sha256(password.encode())
        pas = open('Keys\Password\password.pem', 'rb')
        oldPassword = pas.read()
        pas.close()
        if(hashPassword.hexdigest().encode() == oldPassword ):
            self.menu(selectButton, IP, password)
        else:
            messagebox.showerror("Login", "Incorrect password")

    def menu(self, user, IP, password):
        self.window.withdraw()
        windowMenu = Toplevel()
        chat = Button(windowMenu, text="Chat", width=20, command=lambda: self.chat(user, IP, password, windowMenu))
        files = Button(windowMenu, text="Sending files", width=20, command=lambda: self.fileTransfer(user, IP, windowMenu))
        exit = Button(windowMenu, text="Exit", width=20, command=self.exit)
        chat.grid(row=2, column=0, padx=100, pady=5)
        files.grid(row=3, column=0, padx=100, pady=5)
        exit.grid(row=4, column=0, padx=100, pady=5)

    def exit(self):
        exit()

    def chat(self, user, IP, password, windowMenu):
        self.windowDestroy(windowMenu)
        self.window.withdraw()
        window_chat = Toplevel()
        text_chat = Text(window_chat, width=60, height=20)
        text_chat.insert(END, 'Safe Chat')
        chat = Chat(user, text_chat, IP, password)
        text_message = Entry(window_chat, width=25)
        send = Button(window_chat, text="Send", width=20, command=lambda: chat.sendMessage(text_message, user))
        text_chat.grid(row=2, column=0,  padx=30, pady=2)
        text_message.grid(row=3, column=0,  padx=30, pady=2)
        send.grid(row=4, column=0,  padx=30, pady=2)

    def fileTransfer(self, user, IP, windowMenu):
        self.windowDestroy(windowMenu)
        self.window.withdraw()
        padx = 15
        pady = 5
        file = FileTransfer(user, IP)
        window_filles = Toplevel()
        lbprogres = Label(window_filles, text="Progress bar: ")
        lbinfo = Label(window_filles, text="Select a file: ")
        pb_frame = Frame(window_filles, width=50)
        pb_frame.place(x=165, y=0, relwidth=1.)
        var = IntVar()
        var.set(10)
        progress = Progressbar(pb_frame, maximum=100, variable=0,  orient='horizontal', mode='determinate')
        fill = Button(window_filles, text="Select a file", width=20, command=lambda: file.choiseFill())
        select_button = StringVar()
        infoselect_encryption = Label(window_filles, text="Type of encryption")
        ecb = Radiobutton(window_filles, variable=select_button, value="1", text="EBC")
        cbc = Radiobutton(window_filles, variable=select_button, value="2", text="CBC")
        cfb = Radiobutton(window_filles, variable=select_button, value="3", text="CFB")
        ofb = Radiobutton(window_filles, variable=select_button, value="4", text="OFB")
        select_button.set("4")
        ok = Button(window_filles, text="Send", width=20, command=lambda: file.choiseEncrypt(progress, self.window, select_button, user))
        lbprogres.grid(row=0, column=0, padx=padx, pady=pady)
        progress.grid(row=1, column=0, columnspan=3, padx=padx, pady=pady)
        lbinfo.grid(row=2, column=0,  padx=padx, pady=pady)
        fill.grid(row=2, column=1, padx=padx, pady=2)
        infoselect_encryption.grid(row=3, column=1, padx=padx, pady=pady)
        ecb.grid(row=4, column=0, padx=padx, pady=pady)
        cbc.grid(row=4, column=1, padx=padx, pady=pady)
        cfb.grid(row=4, column=2, padx=padx, pady=pady)
        ofb.grid(row=4, column=3, padx=padx, pady=pady)
        ok.grid(row=5, column=1, padx=padx, pady=pady)


    def windowDestroy(self, dwindow):
        dwindow.destroy()
        self.window.update()
        self.window.deiconify()



start = Gui()