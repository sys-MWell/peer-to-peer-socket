import tkinter
from tkinter import *
from clientData import User_Data
from clientMain import Main_Display
import socket
from clientConnection import Socket_Loop


class Master_Display:
    def __init__(self, master):
        self.master = master
        # Collect data from clientData program
        self.userData = User_Data()
        self.programName = self.userData.programName
        self.backgroundColour = self.userData.background
        self.screenSize = self.userData.screenSize

        # Assign host and port
        self.host = self.userData.host
        self.port = self.userData.port

        # -6, 0 = coordinates, upper left of screen
        self.master.geometry(self.screenSize)
        self.master.geometry("+{}+{}".format(-6, 0))

        # Makes it so screen can't be resized
        self.master.resizable(width=False, height=False)

        # Configure background
        self.master.config(bg=self.backgroundColour)

        # Creation of main frame
        self.frame = Frame(self.master, bg=self.backgroundColour)
        self.frame.configure(pady=120)
        self.frame.pack()

        # Try statement, checks for successful connection
        try:
            # Connect to server using the servers host address and port
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect((self.host, self.port))
            Main_Display(self.frame, self.master, self.sock)
            Socket_Loop(self.master, self.sock)
        except:
            # Appropriate error message
            tkinter.messagebox.showerror('ERROR', "Connection error")
            self.master.destroy()

# Start program, instantiate Tkinter library
display = Tk()
app = Master_Display(display)
display.mainloop()
