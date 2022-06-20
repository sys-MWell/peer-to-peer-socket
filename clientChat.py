import threading
import tkinter
from tkinter import *
import os
import tkinter.scrolledtext
from clientData import User_Data


class Chat_Client:
    def __init__(self, frame, master, username, recSocket):

        # Diffie-hellman key exchange variables
        #--#
        self.clientPublicKey = 197
        self.clientPrivateKey = 199
        self.serverPublicKey = None

        self.clientEncryption = None
        self.clientPartialEncryption = None
        self.clientFullEncryption = None
        self.serverPartialKey = None
        #--#

        # Parameter variable declaration
        self.connectedUsers = ''
        self.sock = recSocket
        self.master = master
        self.username = username

        # Collect variables from clientData.py
        self.userData = User_Data()
        self.programName = self.userData.programName
        self.master.title(self.programName + ' - Chat client')
        self.frame = frame
        self.frame.configure(pady=40)

        # Check thread states
        self.guiDone = False
        self.running = True

        # Declares threads for the GUI and received data from the server
        guiThread = threading.Thread(target=self.Gui_Loop)
        receiveThread = threading.Thread(target=self.Receive)

        # Send request to server to accept client connection and username
        self.sock.send("USER".encode('utf-8'))

        # Starts threads
        guiThread.start()
        receiveThread.start()

    # Display GUI
    def Gui_Loop(self):
        # Connected user frame
        self.usernameListFrame = LabelFrame(self.frame, relief='ridge', bg='white', bd=5, pady=15, padx=50)
        self.usernameListFrame.grid(row=1, column=0)

        # Connected user label
        self.usernameListLabel = tkinter.Label(self.usernameListFrame, text="Online users: ", bg="lightgray")
        self.usernameListLabel.config(font=("Arial", 12))
        self.usernameListLabel.grid(padx=5, pady=5)

        self.usernameListTextArea = tkinter.scrolledtext.ScrolledText(self.usernameListFrame, width=20, height=35)
        self.usernameListTextArea.grid(padx=5, pady=5)
        self.usernameListTextArea.config(state='disabled')

        # Chat screen
        self.chatFrame = LabelFrame(self.frame, relief='ridge', bg='white', bd=5, pady=15, padx=120)
        self.chatFrame.grid(row=1, column=1)

        # Chat title label
        self.chatLabel = tkinter.Label(self.chatFrame, text="Chat:", bg="lightgray")
        self.chatLabel.config(font=("Arial", 12))
        self.chatLabel.grid(padx=20, pady=5)

        # Message (data) display
        self.textArea = tkinter.scrolledtext.ScrolledText(self.chatFrame)
        self.textArea.grid(padx=20, pady=5)
        self.textArea.config(state='disabled')

        # Message box title label
        self.msgLabel = tkinter.Label(self.chatFrame, text="Message:", bg="lightgray")
        self.msgLabel.config(font=("Ariel", 12))
        self.msgLabel.grid(padx=20, pady=5)

        # Text box
        self.inputArea = tkinter.Text(self.chatFrame, height=3)
        self.inputArea.grid(padx=20, pady=5)

        # Send button
        self.sendBtn = tkinter.Button(self.chatFrame, text="Send", command=self.Write)
        self.sendBtn.config(font=("Arial", 12))
        self.sendBtn.grid(padx=20, pady=5)

        # Back button
        self.backBtn = tkinter.Button(self.chatFrame, text="Logout", command=self.Logout_Button)
        self.backBtn.config(font=("Arial", 12))
        self.backBtn.grid(padx=20, pady=5)

        # Change thread state
        self.guiDone = True

    # Write message to appear on clients screen -> sends data to server to be broadcast
    def Write(self):
        message = f"MSGR{self.username}: {self.inputArea.get('1.0', 'end')}"
        print("ENCRYPT MESSAGE: "+message)
        test = self.clientEncryption.Encrypt_Message(message)
        self.sock.send(test.encode('utf-8'))
        self.inputArea.delete('1.0', 'end')

    # Closes application if connection is disrupted
    def Stop(self):
        self.running = False
        self.chatFrame.destroy()
        self.sock.close()
        exit(0)

    # Back button
    def Logout_Button(self):
        logoutAccount = tkinter.messagebox.askyesno('Message', "Are you sure you want to logout?")
        if logoutAccount > 0:
            self.sock.send("DISC".encode('utf-8'))
            self.sock.send((self.clientEncryption.Encrypt_Message(self.username)).encode('utf-8'))
            self.master.destroy()
            os.system('clientLoad.py')
            exit()

    # Online user status
    def Refresh_Loop(self):
        try:
            # Update online users list
            self.sock.send("UNRQ".encode('utf-8'))
            self.usernameListTextArea.config(state='normal')
            self.usernameListTextArea.delete('1.0', END)
            for i in range(1, len(self.connectedUsers)):
                self.usernameListTextArea.insert('end', (self.connectedUsers[i] + "\n"))
                self.usernameListTextArea.yview('end')
            self.usernameListTextArea.config(state='disabled')
        except:
            print("Loading list...")
        # Loop every 5 seconds
        self.master.after(5000, self.Loop)

    # Online user status loop, will be called every 5 seconds
    def Loop(self):
        self.Refresh_Loop()

    # Receive data from server
    def Receive(self):
        # Runs while connected
        while self.running:
            try:
                # Receives data from server
                message = self.sock.recv(1024).decode('utf-8')
                if message[:4] != "UNRC":
                    print("Data received from server: "+message)

                # If message is encrypted/ciphertext
                if message[:4] == '':
                    try:
                        decrypt = self.clientEncryption.Decrypt_Message(message)
                        print("DECRYPTED MESSAGE: "+decrypt)
                        data = decrypt
                        message = decrypt
                    except:
                        print("Decryption not in progress")

                # Connects a new user, establishes a peer-to-peer encrypted connection
                if message[:4] == 'USER':
                    newMessage = (self.username + "|" + str(self.clientPublicKey))
                    # Send username and client public key to the server
                    self.sock.send(newMessage.encode('utf-8'))
                    # Receives servers public key
                    self.serverPublicKey = self.sock.recv(1024).decode('utf-8')
                    serverPublicKey = int(self.serverPublicKey)
                    print("Server public key: " + self.serverPublicKey)
                    # Instantiate class properties for encryption
                    self.clientEncryption = DH_Encryption(self.clientPublicKey, serverPublicKey,
                                                          self.clientPrivateKey)
                    # Generate client partial key
                    self.clientPartialEncryption = self.clientEncryption.Generate_Partial_Key()
                    print("Client partial key: " + str(self.clientPartialEncryption))
                    # Receive server partial key
                    self.serverPartialKey = self.sock.recv(1024).decode('utf-8')
                    print("Server partial key: " + str(self.serverPartialKey))
                    # Send client partial key to server
                    self.sock.send(str(self.clientPartialEncryption).encode('utf-8'))
                    serverPartialKey = int(self.serverPartialKey)
                    # Generate client full encryption key
                    self.clientFullEncryption = self.clientEncryption.Generate_Full_Key(serverPartialKey)
                    print("FULL ENCRYPTION: " + str(self.clientFullEncryption))
                    connectedMsg = self.sock.recv(1024).decode('utf-8')
                    print(connectedMsg)
                    self.Refresh_Loop()

                    # If a message is received during the connection process
                    if connectedMsg[:4] == "MSGS":
                        if self.guiDone:
                            self.textArea.config(state='normal')
                            self.textArea.insert('end', connectedMsg)
                            self.textArea.yview('end')
                            self.textArea.config(state='disabled')

                # Display data (messages) from server to clients front end screen
                elif message[:4] == 'MSGR':
                    if self.guiDone:
                        # Removed command from data
                        message = message[4:]
                        # Displays messages that are not blank
                        if (len(message) - len(self.username)) > 3:
                            self.textArea.config(state='normal')
                            self.textArea.insert('end', message)
                            self.textArea.yview('end')
                            self.textArea.config(state='disabled')

                # If servers sends a username receive command
                elif message[:4] == 'UNRC':
                    stringMessage = str(message)
                    try:
                        stringMessage = stringMessage.split("|")
                    except:
                        print("An UNRC error has occurred")
                    self.connectedUsers = stringMessage
            # Exceptions for if connection to server is lost
            except ConnectionAbortedError:
                break
            except:
                print("An connection error has occurred")
                self.sock.close()
                break

# Diffie-hellman encryption algorithms
class DH_Encryption(object):
    def __init__(self, userPublicKey, serverPublicKey, userPrivateKey):
        # Encryption variables
        self.userPublicKey = userPublicKey
        self.serverPublicKey = serverPublicKey
        self.userPrivateKey = userPrivateKey
        # Full encryption key
        self.fullKey = None

    def Generate_Partial_Key(self):
        partialKey = self.userPublicKey ** self.userPrivateKey
        partialKey = partialKey % self.serverPublicKey
        return partialKey

    def Generate_Full_Key(self, partialKeyR):
        fullKey = partialKeyR ** self.userPrivateKey
        fullKey = fullKey % self.serverPublicKey
        self.fullKey = fullKey
        return fullKey

    def Encrypt_Message(self, message):
        encryptedMessage = ""
        key = self.fullKey
        # For every character in the message
        for c in message:
            encryptedMessage += chr(ord(c) + key)
        return encryptedMessage

    def Decrypt_Message(self, encryptedMessage):
        decryptedMessage = ""
        key = self.fullKey
        # For every character in the encrypted massage
        for c in encryptedMessage:
            decryptedMessage += chr(ord(c) - key)
        return decryptedMessage
