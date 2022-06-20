import socket
import threading
import sqlite3
import time

class Server_Startup:
    def __init__(self):

        # Database file name
        self.databaseName = "User_Data.db"

        # Diffie-hellman key exchange variables
        self.serverPublicKey = 151
        self.serverPrivateKey = 157
        self.clientPublicKey = None

        self.serverEncryption = None
        self.serverPartialEncryption = None
        self.serverFullEncryption = None
        self.clientPartialKey = None

        # Assign IP, for demonstrations is the local host and port number
        self.host = '127.0.0.1'
        self.port = 50010

        # Setup socket connectivity
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((self.host, self.port))
        self.server.listen()

        # Valid server commands
        self.valid_commands = ["CONN", "MSGS", "MSGR", "REGD", "LOGD", "USER", "NICK", "UNRQ", "DISC"]

        # Array to hold the connected user's addresses and usernames
        self.connectedAddresses = []
        self.connectedUsernames = []
        self.connectedUserPorts = []

        # Run method, to instantiate a new connection
        self.newConnection()

    # Establish a new connection
    def newConnection(self):
        while True:
            # Assigns server library commands to client variable
            client, address = self.server.accept()
            print(f"connected with {str(address)}!")
            # Starts thread to constantly receive data from client
            self.thread = threading.Thread(target=self.receive, args=(client,address,))
            self.thread.start()

    # Receive commands from client
    def receive(self,client,address):
        try:
            # Loop for while connection is active
            while True:
                # Receive commands
                data = client.recv(1024)
                # if something other than data is sent -> response disregarded
                if not data:
                    break

                # Decodes byte data
                command = data.decode('utf-8')[:4]

                # If command sent from client is a username request
                if command != 'UNRQ':
                    print("command = "+command)
                    print("Data received from client: "+data.decode('utf-8'))

                # If message needs decrypting
                if command == '':
                    try:
                        decryptData = data.decode('utf-8')
                        # Decrypt ciphertext into plaintext
                        decrypt = self.serverEncryption.Decrypt_Message(decryptData)
                        print("DECRYPTED MESSAGE: "+decrypt)
                        data = decrypt
                        command = decrypt[:4]
                    except:
                        print("Decryption not in progress")

                # Data validation for command
                if len(command) < 4:
                    response = "Invalid command"
                else:
                    if command not in self.valid_commands:
                        response = "Invalid command"
                    else:
                        # If client sent a username send command
                        if command == "USER":
                            client.send("USER".encode('utf-8'))
                            usernameData = client.recv(1024)
                            usernameReceived = usernameData.decode('utf-8')
                            # Send server public key to client
                            client.send((str(self.serverPublicKey)).encode('utf-8'))
                            # Spit data into username and key
                            receivedData = usernameReceived.split("|")
                            username = receivedData[0]
                            self.clientPublicKey = receivedData[1]
                            clientPublicKey = int(self.clientPublicKey)

                            # Instantiate class properties for encryption
                            self.serverEncryption = DH_Encryption(clientPublicKey, self.serverPublicKey,
                                                                  self.serverPrivateKey)
                            # Generate server partial key
                            self.serverPartialEncryption = self.serverEncryption.Generate_Partial_Key()
                            print("Server partial key: "+str(self.serverPartialEncryption))
                            # Send server partial key to client
                            client.send((str(self.serverPartialEncryption)).encode('utf-8'))
                            # Receive client partial key
                            self.clientPartialKey = client.recv(1024).decode('utf-8')
                            print("Client partial key: "+str(self.clientPartialKey))
                            # Generate server full encryption key
                            clientPartialKey = int(self.clientPartialKey)
                            self.serverFullEncryption = self.serverEncryption.Generate_Full_Key(clientPartialKey)
                            print("FULL ENCRYPTION: " + str(self.serverFullEncryption))

                            # Append username and address to arrays
                            self.connectedUsernames.append(username)
                            self.connectedUserPorts.append(address)
                            self.connectedAddresses.append(client)

                            # Announce new user to connected clients
                            print(f"Nickname of client is {username}")
                            client.send(f"MSGSWelcome {username} to Chatsy!".encode('utf-8'))
                            self.broadcast(f"MSGR{username} connected to the server!\n".encode('utf-8'))

                        # If client sent a message receive command
                        elif command == "MSGR":
                            try:
                                # Encrypt data to be sent to client
                                encrypt = self.serverEncryption.Encrypt_message(data)
                                self.broadcast(encrypt.encode('utf-8'))
                            except:
                                self.broadcast(data)

                        # If client sent a username request command
                        elif command == "UNRQ":
                            unrcCommand = 'UNRC'
                            for i in range(len(self.connectedUsernames)):
                                unrcCommand = unrcCommand + "|" + str(self.connectedUsernames[i])
                            client.send((str(unrcCommand)).encode('utf-8'))

                        # If client sent a connection command
                        elif command == "CONN":
                            print("Connection established using CONN command")
                            # Receive username from client
                            clientData = client.recv(1024)
                            usernameReceived = clientData.decode('utf-8')

                            # Send server public key to client
                            client.send((str(self.serverPublicKey)).encode('utf-8'))

                            # Client public key received
                            self.clientPublicKey = usernameReceived
                            clientPublicKey = int(self.clientPublicKey)

                            # Instantiate class properties for encryption
                            self.serverEncryption = DH_Encryption(clientPublicKey, self.serverPublicKey,
                                                                  self.serverPrivateKey)
                            # Generate server partial key
                            self.serverPartialEncryption = self.serverEncryption.Generate_Partial_Key()
                            print("server partial key: "+str(self.serverPartialEncryption))
                            # Send server partial key to client
                            client.send((str(self.serverPartialEncryption)).encode('utf-8'))
                            # Receive client partial key
                            self.clientPartialKey = client.recv(1024).decode('utf-8')
                            print("Client partial key: "+str(self.clientPartialKey))
                            # Generate server full encryption key
                            clientPartialKey = int(self.clientPartialKey)
                            self.serverFullEncryption = self.serverEncryption.Generate_Full_Key(clientPartialKey)
                            print("FULL ENCRYPTION: " + str(self.serverFullEncryption))

                        # If client sent a login data command
                        elif command == "LOGD":
                            # Receive username
                            logUsernameCipher = client.recv(1024).decode('utf-8')
                            time.sleep(1)
                            # Receive password
                            logPasswordCipher = client.recv(1024).decode('utf-8')
                            # Decrypt username and password received from server from ciphertext to plaintext
                            enteredUsername = self.serverEncryption.Decrypt_Message(logUsernameCipher)
                            #enteredUsername = logUsernameCipher
                            enteredPassword = self.serverEncryption.Decrypt_Message(logPasswordCipher)
                            #enteredPassword = logPasswordCipher

                            # Check database for username and password within the User_Details table
                            try:
                                with sqlite3.connect(self.databaseName) as db:
                                    dbConnect = db.cursor()
                                    # SQL query code to search UserData.DB database
                                    findUsername = (
                                        'SELECT Username, Password FROM User_Details WHERE Username = ? and Password = ?')
                                    # Execute query code
                                    dbConnect.execute(findUsername, [(enteredUsername), (enteredPassword)])
                                    # Fetch all results corresponding to query
                                    receivedResult = dbConnect.fetchall()
                                    for row in receivedResult:
                                        fetchedUsername = row[0]
                                        fetchedPassword = row[1]

                            except:
                                print("Database error")

                            try:
                                # Encrypt username and password to send back to client
                                usernameEncrypt = self.serverEncryption.Encrypt_message(fetchedUsername)
                                passwordEncrypt = self.serverEncryption.Encrypt_message(fetchedPassword)

                                client.send(usernameEncrypt.encode('utf-8'))
                                client.send(passwordEncrypt.encode('utf-8'))
                            except:
                                # If database query couldn't SELECT table contents an error message is sent to client
                                errorMessage = self.serverEncryption.Encrypt_message("ERROR")
                                client.send(errorMessage.encode('utf-8'))
                                client.send(errorMessage.encode('utf-8'))
                            db.close()

                        # If client sends a register data command
                        elif command == "REGD":
                            # Receive username and password from client
                            regUsernameCipher = client.recv(1024).decode('utf-8')
                            regPasswordCipher = client.recv(1024).decode('utf-8')

                            # Decrypt username and password received from client
                            regUsername = self.serverEncryption.Decrypt_Message(regUsernameCipher)
                            regPassword = self.serverEncryption.Decrypt_Message(regPasswordCipher)

                            # Connect to database
                            with sqlite3.connect(self.databaseName) as db:
                                cursor = db.cursor()
                                # This query code creates the database and user_details table if it doesn't already exist
                                cursor.execute('''CREATE TABLE IF NOT EXISTS user_details
                                                  (UserID integer,
                                                  Username text,
                                                  Password text,
                                                  primary key(UserID))''')
                                # This query code checks to see whether the username entered already exists or not
                                cursor.execute('''SELECT username FROM user_details WHERE username=?''',
                                                    (regUsername,))
                                exists = cursor.fetchone()

                                # If the Username does not exist the data is added to the database, if it does exist
                                # an appropriate error message is given
                                if not exists:
                                    cursor.execute(
                                        'INSERT INTO user_details (Username,Password) VALUES(?,?)'
                                        , (regUsername, regPassword))
                                    # If query result was a success
                                    regResult = 'SUCC'
                                    print('Message', "Signup successful!")
                                else:
                                    # If query result failed
                                    regResult = "FAIL"
                                    print('Error', 'Username already exists, try another...')

                            # Send boolean result to client
                            client.send(regResult.encode('utf-8'))
                            # Close database connection
                            db.close()

                        # If command from client is disconnect
                        elif command == "DISC":
                            # Receive username from client
                            recUsernameCipher = client.recv(1024).decode('utf-8')
                            # Decrypt username
                            discUsername = self.serverEncryption.Decrypt_Message(recUsernameCipher)
                            # Find index of username with connectedUsernames array
                            addIndex = self.connectedUsernames.index(discUsername)
                            # Remove username from array
                            self.connectedUsernames.remove(discUsername)
                            # Remove address from connectedAddresses array
                            discAddress = self.connectedUserPorts[addIndex]
                            print(f"Client {discUsername}, at address {str(discAddress)} has disconnected")
                            self.connectedAddresses.pop(addIndex)
                            self.connectedUserPorts.pop(addIndex)
                            # Broadcast disconnect message to all connected clients
                            self.broadcast(f"MSGR{discUsername} disconnected from the server!\n".encode('utf-8'))


        except ConnectionAbortedError:
                print("ConnectionAbortedError")
        except:
            print("An connection error has occurred")

    # broadcast messages to all connected clients
    def broadcast(self,message):
        for client in self.connectedAddresses:
            client.send(message)

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

    def Encrypt_message(self, message):
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

# Start server
print("Server running...")
Server_Startup()
