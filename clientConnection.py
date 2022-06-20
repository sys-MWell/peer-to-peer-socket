import tkinter

# Detect a connection, if no connection is found application closes
class Socket_Loop:
    def __init__(self, master, recSocket):
        self.master = master
        self.sock = recSocket
        # Call function connection_loop, checks the active server connection
        self.connection_loop()

    def connection_loop(self):
        try:
            # Sends PING command to server, checks connection
            self.sock.send('PING'.encode('utf-8'))
        except:
            # Displays appropriate error message
            self.Exit_Program = tkinter.messagebox.showerror('ERROR', "Connection lost")
            self.master.destroy()

