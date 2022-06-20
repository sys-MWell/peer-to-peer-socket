import tkinter
from tkinter import *
from tkinter.messagebox import showinfo, showerror
from clientData import *
from clientChat import Chat_Client
import time
from clientConnection import Socket_Loop

class Main_Display:
    # Initialise the attributes
    # Master = display
    def __init__(self, frame, master, recSocket):

        # Collects data from clientData
        self.userdata = User_Data()
        self.programName = self.userdata.programName
        self.master = master
        self.sock = recSocket

        self.frame = frame
        self.master.title(self.programName + ' - Main Menu')

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~Main menu buttons~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating the frame for the buttons to go in
        self.btnFrame = LabelFrame(self.frame, relief='ridge', bg='white', bd=5, pady=15, padx=200)
        self.btnFrame.grid(row=1, column=0)

        self.lblMenuTitle = Label(self.btnFrame, text=("Welcome to " + self.programName + "!")
                                  , font=('arial', 25, 'bold'), bg='white', fg='black')
        self.lblMenuTitle.grid(row=0, column=0, columnspan=2, pady=60)


        # Creating the buttons for the main menu
        self.btnLogin = Button(self.btnFrame, text='Login', height='2', width='25'
                               , font=('ariel', 15, 'bold'), bg='gainsboro', command=self.Login_Option)
        self.btnLogin.grid(row=2, column=0, pady=8, padx=8)
        self.btnRegister = Button(self.btnFrame, text='Register', height='2', width='25'
                                  , font=('ariel', 15, 'bold'), bg='gainsboro', command=self.Registration_Option)
        self.btnRegister.grid(row=3, column=0, pady=8)
        self.btnExit = Button(self.btnFrame, text='Exit', height='2', width='17'
                              , font=('ariel', 10, 'bold'), bg='gainsboro', command=self.Exit_Program)
        self.btnExit.grid(row=4, column=0, pady=8)

    # Loads login page - Login button
    def Login_Option(self):
        self.btnFrame.destroy()
        Socket_Loop(self.master, self.sock)
        Login_Frame(self.frame, self.master, self.sock)

    # Load registration page - Register button
    def Registration_Option(self):
        self.btnFrame.destroy()
        Socket_Loop(self.master, self.sock)
        Register_Frame(self.frame, self.master, self.sock)

    # Closes program - Exit button
    def Exit_Program(self):
        exitProgram = tkinter.messagebox.askyesno('Message', "Confirm if you want to exit")
        if exitProgram > 0:
            self.master.destroy()

class Login_Frame():
    def __init__(self, frame, master, recSocket):

        # Diffie-hellman key exchange variables
        self.clientPublicKey = 197
        self.clientPrivateKey = 199
        self.serverPublicKey = None

        self.clientEncryption = None
        self.clientPartialEncryption = None
        self.clientFullEncryption = None
        self.serverPartialKey = None

        # Login_Frame variables
        #---------#
        self.enteredUsername = StringVar()
        self.enteredPassword = StringVar()
        self.hiddenText = "*"
        self.highlightedColour = '#FFFFFF'
        self.fetchedUsername = ""
        self.fetchedPassword = ""

        # Collect variables from clientData
        self.userData = User_Data()
        self.programName = self.userData.programName
        self.backgroundColour = self.userData.background
        self.screenSize = self.userData.screenSize
        self.databaseName = self.userData.userDatabase
        self.sock = recSocket
        #---------#

        # Display frame attributes
        self.frame = frame
        self.frame.configure(pady=120)
        self.master = master
        self.master.title(self.programName + ' - Login')

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~Main menu buttons~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating the frame for the buttons to go in
        self.loginFrame = LabelFrame(self.frame, relief='ridge', bg='white', bd=5, pady=15, padx=200)
        self.loginFrame.grid(row=1, column=0)

        self.lblLoginTitle = Label(self.loginFrame, text=("Login"),
                                  font=('arial', 25, 'bold'), bg='white',
                                  fg='black')
        self.lblLoginTitle.grid(row=0, column=0, columnspan=2, pady=60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Entry box frame~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        self.entryBoxFrame = LabelFrame(self.loginFrame, relief='ridge', bg='white', bd=5, pady=15, padx=10)
        self.entryBoxFrame.grid(row=1, column=0)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Labels and entries for login~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating the username label
        self.lblUsername = Label(self.entryBoxFrame, text='Username', font=('ariel', 20, 'bold'), bd=5,
                                 bg=self.highlightedColour, fg='black')
        self.lblUsername.grid(row=3, column=0, padx=10, pady=10)

        # Creating the username entry box
        self.txtUsername = Entry(self.entryBoxFrame, font=('ariel', 20), textvariable=self.enteredUsername)
        self.txtUsername.grid(row=3, column=1, padx=10)

        # Creating the password label
        self.lblPassword = Label(self.entryBoxFrame, text='Password'
                                 , font=('ariel', 20, 'bold'), bd=5,
                                 bg=self.highlightedColour, fg='Black')
        self.lblPassword.grid(row=4, column=0)

        # Creating the password entry box
        self.txtPassword = Entry(self.entryBoxFrame, font=('ariel', 20), show=self.hiddenText
                                 , textvariable=self.enteredPassword)
        self.txtPassword.grid(row=4, column=1, columnspan=2, pady=10)

        #~~~~~~~~~~~~~~~~~~~~~~~~~Creating check button to show/hide password~~~~~~~~~~~~~~~~~~~~~~
        self.loginShowPass = Checkbutton(self.entryBoxFrame, text = "Hide Password", onvalue=True, offvalue=False
                                      , bg = 'white',command = self.Update_Password_Txt)
        self.loginShowPass.grid(row = 5, column = 0)
        self.loginShowPass.var = BooleanVar(value=True)
        self.loginShowPass['variable'] = self.loginShowPass.var

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Login Button~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creation of the login button
        self.btnLogin = Button(self.entryBoxFrame, text='Login', width=17, font=('ariel', 10, 'bold')
                               , command=self.Login_System)  # runs the subroutine Login_Systems
        self.btnLogin.grid(row=7, column=0, pady=8, padx=8)
        self.btnLogin.place(relx=0.5, rely=0.9, anchor=CENTER)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Back Button~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating of the back button
        self.btnBack = Button(self.entryBoxFrame, text='Back', width=17, font=('ariel', 10, 'bold')
                              , command=self.Back_Button)
        self.btnBack.config(height=1, width=5)
        self.btnBack.place(relx=0.01, rely=0.9, anchor=NW)

        self.lblTitle3 = Label(self.entryBoxFrame, text='', bg='white')
        self.lblTitle3.grid(row=7, column=0, columnspan=1, pady=20)

    def Connect(self):
        # Send connection command
        self.sock.send("CONN".encode('utf-8'))
        time.sleep(1)
        strClientPublicKey = str(self.clientPublicKey)
        # Send client public key to the server
        self.sock.send(strClientPublicKey.encode('utf-8'))
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

    def Login_System(self):
        Socket_Loop(self.master, self.sock)
        if self.serverPublicKey == None:
            self.Connect()

        # Send login data
        self.sock.send("LOGD".encode('utf-8'))
        time.sleep(1)
        # Send username and password to server
        self.sock.send((self.clientEncryption.Encrypt_Message(self.enteredUsername.get())).encode('utf-8'))
        #self.sock.send((self.enteredUsername.get()).encode('utf-8'))
        time.sleep(1)
        self.sock.send((self.clientEncryption.Encrypt_Message(self.enteredPassword.get())).encode('utf-8'))
        #self.sock.send((self.enteredPassword.get()).encode('utf-8'))

        # Receive data from server
        self.fetchedUsername = self.sock.recv(1024).decode('utf-8')
        self.fetchedPassword = self.sock.recv(1024).decode('utf-8')

        # Decrypt data
        usernameDecrypt = self.clientEncryption.Decrypt_Message(self.fetchedUsername)
        passwordDecrypt = self.clientEncryption.Decrypt_Message(self.fetchedPassword)

        # Checks for errors within the data received from the server
        if (usernameDecrypt == 'ERROR') and (passwordDecrypt == 'ERROR'):
            tkinter.messagebox.showerror('ERROR', "Incorrect details entered")
        else:
            # If username and password match, user may login
            if (usernameDecrypt == self.enteredUsername.get()) and (passwordDecrypt == self.enteredPassword.get()):
                self.loginFrame.destroy()

                Chat_Client(self.frame,self.master,usernameDecrypt,self.sock)
            else:
                print("details incorrect")

    def Back_Button(self):
        self.loginFrame.destroy()
        Socket_Loop(self.master, self.sock)
        Main_Display(self.frame,self.master,self.sock)

    def Update_Password_Txt(self):
        if self.loginShowPass.var.get():
            self.txtPassword['show'] = "*"
        else:
            self.txtPassword['show'] = ""

class Register_Frame():
    def __init__(self, frame, master, recSocket):

        # Deffie-hellman public and private key variables
        self.clientPublicKey = 197
        self.clientPrivateKey = 199
        self.serverPublicKey = None

        self.clientEncryption = None
        self.clientPartialEncryption = None
        self.clientFullEncryption = None
        self.serverPartialKey = None

        # String variables for username and password
        self.enteredUsername = StringVar()
        self.enteredPassword = StringVar()
        self.registerHiddenText = "*"
        self.highlightedColour = '#FFFFFF'

        # Socket
        self.sock = recSocket

        # Collect user data
        self.userData = User_Data()
        self.programName = self.userData.programName
        self.backgroundColour = self.userData.background
        self.screenSize = self.userData.screenSize
        self.databaseName = self.userData.userDatabase

        self.frame = frame
        self.frame.configure(pady=120)
        self.master = master
        self.master.title(self.programName + ' - Register')

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~Main menu buttons~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating the frame for the buttons to go in
        self.registerFrame = LabelFrame(self.frame, relief='ridge', bg='white', bd=5, pady=15, padx=200)
        self.registerFrame.grid(row=1, column=0)

        self.lblRegisterTitle = Label(self.registerFrame, text=("Register"),
                                   font=('arial', 25, 'bold'), bg='white',
                                   fg='black')
        self.lblRegisterTitle.grid(row=0, column=0, columnspan=2, pady=60)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Entry box frame~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        self.registerEntryBoxFrame = LabelFrame(self.registerFrame, relief='ridge', bg='white', bd=5, pady=15, padx=10)
        self.registerEntryBoxFrame.grid(row=1, column=0)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Labels and entries for login~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating the username label
        self.lblRegisterUsername = Label(self.registerEntryBoxFrame, text='Username', font=('ariel', 20, 'bold'), bd=5,
                                 bg=self.highlightedColour, fg='black')
        self.lblRegisterUsername.grid(row=3, column=0, padx=10, pady=10)

        # Creating the username entry box
        self.txtRegisterUsername = Entry(self.registerEntryBoxFrame, font=('ariel', 20)
                                         , textvariable=self.enteredUsername)
        self.txtRegisterUsername.grid(row=3, column=1, padx=10)

        # Creating the password label
        self.lblRegisterPassword = Label(self.registerEntryBoxFrame, text='Password'
                                 , font=('ariel', 20, 'bold'), bd=5,
                                 bg=self.highlightedColour, fg='Black')
        self.lblRegisterPassword.grid(row=4, column=0)

        # Creating the password entry box
        self.txtRegisterPassword = Entry(self.registerEntryBoxFrame, font=('ariel', 20), show=self.registerHiddenText,
                                 textvariable=self.enteredPassword)
        self.txtRegisterPassword.grid(row=4, column=1, columnspan=2, pady=10)

        # ~~~~~~~~~~~~~~~~~~~~~~~~~Creating check button to show/hide password~~~~~~~~~~~~~~~~~~~~~~
        self.registerShowPass = Checkbutton(self.registerEntryBoxFrame, text="Hide Password"
                                         , onvalue=True, offvalue=False
                                         , bg='white', command=self.Update_Password_Txt)
        self.registerShowPass.grid(row=5, column=0)
        self.registerShowPass.var = BooleanVar(value=True)
        self.registerShowPass['variable'] = self.registerShowPass.var

        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Register Button~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creation of the register button
        self.btnRegister = Button(self.registerEntryBoxFrame, text='Register', width=17, font=('ariel', 10, 'bold')
                               , command=self.Check_Data)
        self.btnRegister.grid(row=7, column=0, pady=8, padx=8)
        self.btnRegister.place(relx=0.5, rely=0.9, anchor=CENTER)
        # ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~Back Button~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        # Creating of the back button
        self.btnRegisterBack = Button(self.registerEntryBoxFrame, text='Back', width=17, font=('ariel', 10, 'bold')
                              , command=self.Back_Button)
        self.btnRegisterBack.config(height=1, width=5)
        self.btnRegisterBack.place(relx=0.01, rely=0.9, anchor=NW)

        self.lblRegisterTitle2 = Label(self.registerEntryBoxFrame, text='', bg='white')
        self.lblRegisterTitle2.grid(row=7, column=0, columnspan=1, pady=20)

    def Check_Data(self):
        Socket_Loop(self.master, self.sock)
        # Data entry check conditions
        self.userCheck = False
        self.passCheck = False
        self.username = self.enteredUsername.get()
        self.password = self.enteredPassword.get()

        # Check conditions for username and password entry
        if self.username == '':
            self.ErrorMessage = showinfo('Message', "Enter a username")
        else:
            # Checks if username is between 5-14 characters long
            if len(self.username) < 5 or len(self.username) > 14:
                self.ErrorMessage = showinfo('Information', "Username must be 5-14 characters long")
            else:
                self.userCheck = True
        if self.password == '':
            self.ErrorMessage = showinfo('Message', "Enter a password")
        else:
            # Checks if password is between 5-14 characters long
            if len(self.password) < 5 or len(self.password) > 14:
                self.ErrorMessage = showinfo('Information', "Password must be 5-14 characters long")
            else:
                self.passCheck = True

        # If username and password check conditions are met, the users data can be registered into the database
        if (self.userCheck == True) and (self.passCheck == True):
            self.Register_Data()

    def Register_Data(self):
        # Check connection to server
        Socket_Loop(self.master, self.sock)
        time.sleep(1)
        # Checks if key is already generated
        if self.serverPublicKey == None:
            self.Connect()

        try:
            # Sends registered data to server
            self.sock.send("REGD".encode('utf-8'))
            time.sleep(0.1)

            # Encrypts username and password
            usernameEncrypt = self.clientEncryption.Encrypt_Message(self.username)
            passwordEncrypt = self.clientEncryption.Encrypt_Message(self.password)

            # Send encrypted data
            self.sock.send(usernameEncrypt.encode('utf-8'))
            time.sleep(1)
            self.sock.send(passwordEncrypt.encode('utf-8'))

            # Fetches result from server
            fetchedResult = self.sock.recv(1024).decode('utf-8')

            # If success command is received
            if fetchedResult == 'SUCC':
                self.registerFrame.destroy()
                Chat_Client(self.frame, self.master, self.username, self.sock)
            # Appropriate error messages
            elif fetchedResult == 'FAIL':
                showerror('Error', 'Username already exists, try another...')
            else:
                showerror('Error', 'Database error has occurred')
        except:
            showerror('Error', 'Database error has occurred')

    def Back_Button(self):
        # Back button
        Socket_Loop(self.master, self.sock)
        self.registerFrame.destroy()
        Main_Display(self.frame, self.master, self.sock)

    def Update_Password_Txt(self):
        # Used to show/hide the users password
        if self.registerShowPass.var.get():
            self.txtRegisterPassword['show'] = "*"
        else:
            self.txtRegisterPassword['show'] = ""

    def Connect(self):
        self.sock.send("CONN".encode('utf-8'))
        strClientPublicKey = (str(self.clientPublicKey))
        time.sleep(1)
        # Send client public key to the server
        self.sock.send(strClientPublicKey.encode('utf-8'))
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

# Diffie-hellman class
class DH_Encryption(object):
    def __init__(self, userPublicKey, serverPublicKey, userPrivateKey):
        self.userPublicKey = userPublicKey
        self.serverPublicKey = serverPublicKey
        self.userPrivateKey = userPrivateKey
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
        for c in message:
            encryptedMessage += chr(ord(c) + key)
        return encryptedMessage

    def Decrypt_Message(self, encryptedMessage):
        decryptedMessage = ""
        key = self.fullKey
        for c in encryptedMessage:
            decryptedMessage += chr(ord(c) - key)
        return decryptedMessage