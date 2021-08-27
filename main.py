# gui for file safe
import io
from tkinter import *

from cv2 import log, namedWindow
from rough import enc

import os
from os import kill, name, replace, system, write
import tkinter as tk
import tkinter
from tkinter import Button, Canvas, Event, Label, Listbox, PhotoImage, Scrollbar, font, mainloop
from tkinter.constants import ACTIVE, ANCHOR, BOTH, CHECKBUTTON, DISABLED, END, LEFT, RIGHT
from PIL import ImageTk, Image
from tkinter import filedialog, messagebox
import hashlib
from tkinter import ttk
import sqlite3
import base64
KEY = 21  # ;;
PREVIEW_EXTENSIONS = ['jpg', 'png', 'JPG', 'PNG']


class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        # useful.. after doing this i m able to use controller in any other class methods i want by using self.controller...
        self.controller = controller
        tk.Frame.__init__(self, parent)

        #self.root.bind('<Return>', self.worked)
        # self.bind('<Key>', self.preview)
        self.initDB()
        self.initUI()
        self.show_data()  # ;;
        # self.listbox.focus_set()

    def show_data(self):
        # dummy..
        # string = "how are u doing man.. this is all righkjsdkf andk this  is me and t be suer abut my positivity is my strength"
        # data = string.split()
        ids, file_names = self.get_stored_file_info()
        self.listbox = Listbox(self, width=40)
        self.listbox.grid(row=3, column=0, columnspan=10)
        self.scrollbar = Scrollbar(self)
        self.scrollbar.grid(row=3, column=10, sticky="nse")
        # https://stackoverflow.com/questions/51973653/tkinter-grid-fill-empty-space/51973754

        # for values in range(100):
        #     self.listbox.insert(END, values)
        for name in file_names:
            self.listbox.insert(END, name)

        self.listbox.config(yscrollcommand=self.scrollbar.set)
        self.scrollbar.config(command=self.listbox.yview)
        # for i, word in enumerate(data):
        #     lbl = tk.Label(self, text=word)
        #     lbl.grid(row=3+i, column=1)
        # ;;
        # bind preview function so that we can preview selected image by pressing Enter key
        self.listbox.bind('<Return>', self.preview)

    def initUI(self):

        label = ttk.Label(self, text="File Path")
        label.grid(row=0, column=4, padx=10, pady=10)
        # 'back to login page'  button <-
        self.back_to_login_button = tk.Button(
            self, text="=", command=lambda: self.back_to_login())  # controller.show_frame(login))
        self.back_to_login_button.grid(row=0, column=0)

        # entrybox to enter path to file manually
        self.entry_text = tk.StringVar()  # type of..
        self.file_path_entry = tk.Entry(self, textvariable=self.entry_text)
        self.file_path_entry.grid(row=0, column=5)
        # or select file using filedialog
        select_file_button = ttk.Button(self, text="select file",
                                        # lambda: controller.show_frame(StartPage))
                                        command=self.select_file)  # putting the button in its place
        select_file_button.grid(row=0, column=7, padx=5, pady=5)

        add_to_safe_button = tk.Button(self, text=" + ", bg='#0000ff', fg='#ffffff', font=('Arial', 13, 'bold'),
                                       # lambda: controller.show_frame(StartPage))
                                       # command=lambda: self.extract_filename(self.file_path_entry.get()), width=8, height=1)
                                       command=self.add_to_safe, width=8, height=1)  # putting the button in its place
        # by using grid
        add_to_safe_button.grid(row=1, column=4, padx=10, pady=10)
        remove_from_safe_button = tk.Button(self, text=" - ", bg='#00ff00', fg='#ffffff', font=('Arial', 13, 'bold'),
                                            # lambda: controller.show_frame(StartPage))
                                            # command=lambda: self.extract_filename(self.file_path_entry.get()), width=8, height=1)
                                            command=self.remove_from_safe, width=8, height=1)  # putting the button in its place
        # by using grid
        remove_from_safe_button.grid(row=1, column=5, padx=10, pady=10)

        # checkbox about saving decrypted file
        self.checked_var = tk.IntVar()
        self.checked_var.set(0)  # set on by default
        cb = ttk.Checkbutton(
            self, text="used", variable=self.checked_var, onvalue=1, offvalue=0)
        cb.grid(row=1, column=6)

        # preview button
        self.preview_button = tk.Button(self, text='|>|', bg='#00ff00', fg='#ffffff', font=('Arial', 13, 'bold'),
                                        command=self.preview, width=6, height=1)
        self.preview_button.grid(row=3, column=13)
        # .preview(e))
        #self.preview_button.bind('<Return>', self.worked)

    def worked(self, event):
        print("worked")

    def initDB(self):
        self.conn = sqlite3.connect('safe01.db')
        try:
            self.conn.execute(
                '''
            CREATE TABLE SAFE
            (ID INTEGER PRIMARY KEY,
            FILE_NAME TEXT NOT NULL,
            FULL_PATH TEXT NOT NULL,
            CONTENT BLOB NOT NULL);
            '''
            )

            print(
                "Your safe has been created!\nWhat would you like to store in it today?")
        except:
            print("You have a safe, what would you like to do today?")

    def back_to_login(self):
        self.controller.show_frame(login)
        self.refresh()

    def get_stored_file_info(self):
        retrieve_cmd = 'SELECT ID,FILE_NAME FROM SAFE'
        cursor = self.conn.execute(retrieve_cmd)
        self.ids = []
        self.file_names = []
        for row in cursor:
            self.ids.append(row[0])
            self.file_names.append(row[1])

        return self.ids, self.file_names

    def select_file(self):
        filename = filedialog.askopenfilename(
            initialdir='C:\\', title="Select file", filetypes=(("all files", "*.*"), ("jpg files", "*.jpg")))
        # initialdir='C:\\' for eg. sets default select dir .. here we are getting this from previously opened folder
        path_to_file = filename  # r'{}'.format(master.filename)

        # by default askopenfilename uses linux like '/' for win we have to use '\'
        # path_to_pdf = path_to_pdf.replace('/', '\\')
        # settings["initialdir"] = path_to_pdf
        self.entry_text.set(path_to_file)

    def remove_from_safe_helper(self):  # ;;
        # select the file (file_name) from the list
        selection_tuple = self.listbox.curselection()
        try:
            selected_index = selection_tuple[0] + 1
        except:
            selected_index = None
        # index of selected file can be used as ID in db
          # .get(ACTIVE))
        # if selected_index is not None:
        if selected_index is None:
            return
        selected_index = self.ids[selected_index-1]

        # select row in db for selected file
        cmd = f'SELECT * FROM SAFE WHERE ID = {str(selected_index)}'
        cursor = self.conn.execute(cmd)

        for row in cursor:
            file_name = row[1]
            stored_full_path = row[2]
            content = row[3]
        #

        extension = stored_full_path.split('.')[-1]
        if extension in PREVIEW_EXTENSIONS:  # ;;
            self.preview_flag = True
        else:
            self.preview_flag = False

        # remove b' and ' from string (content was stored as string in db..
        # so we need to take extra chars to have a pure string that can be converted to bytes string)
        content = content[2:-1]
        content = bytes(content, 'utf-8')

        decoded = base64.b64decode(content)  # b64 decode
        # bytes->bytesarray.. convert to bytearray so that it can be changed(manipulated)
        decoded = bytearray(decoded)
        # manipulate (do XOR operation)
        final_decoded_data = self.manipulate(decoded, KEY)
        return selected_index, file_name, extension, stored_full_path, final_decoded_data

    def remove_from_safe(self):
        if self.remove_from_safe_helper() is None:
            return
        selected_index, file_name, extension, stored_full_path, final = self.remove_from_safe_helper()
        # save final content to file
        # store the file to 'full_path' eg. C:/users/er/dc/inl.jpg
        if self.checked_var.get() == 1:
            # if checkbox(use default path) is checked then store file to the location where it came from
            full_path_to_save_file = stored_full_path
        else:
            full_path_to_save_file = filedialog.asksaveasfilename(title='Save File As',
                                                                  initialdir='C:\\', defaultextension=extension, initialfile=file_name)  # filetypes=(("all files", "*.*"))

            # adding file extension manually to path ..
            # full_path_to_save_file += ('.'+extension)
            # full_path_to_save_file

        # save the file
        try:
            with open(full_path_to_save_file, 'wb') as f:  # ;;
                f.write(final)
                # remove from db after decrypting and saving
                c = f'DELETE FROM SAFE WHERE ID = {str(selected_index)}'
                self.conn.execute(c)
                self.conn.commit()
                self.refresh()
        except Exception as e:
            print(e)

    def add_to_safe(self):
        # print(self.scrollbar.get(self))
        print(f" {self.file_path_entry.get()}  Added")
        # ;;
        ENCRYPTED_CONTENT = self.encrypt(self.file_path_entry.get(), KEY)

        if not ENCRYPTED_CONTENT:  # if encrypt() returns False because of some error
            return  # then we dont need to do other operations

        # encoding into b64 so that to avoid problem because of special chars(that cause sytax error .. interfere with sql queries)
        ENCRYPTED_CONTENT = base64.b64encode(ENCRYPTED_CONTENT)

        FULL_PATH = self.file_path_entry.get()
        FILE_NAME = self.extract_filename(self.file_path_entry.get())

        # command = 'INSERT INTO SAFE (FILE_NAME, FULL_PATH, CONTENT) VALUES (%s, %s, %s);' % (
        #     '"' + FILE_NAME + '"', '"' + FULL_PATH + '"', '"'+str(ENCRYPTED_CONTENT)+'"')
        command = f'''INSERT INTO SAFE (FILE_NAME,FULL_PATH,CONTENT) VALUES ("{FILE_NAME}","{FULL_PATH}","{ENCRYPTED_CONTENT}");'''
        self.conn.execute(command)
        self.conn.commit()

        print(f" Successfully Encrypted {self.file_path_entry.get()}")
        FULL_PATH = FULL_PATH.replace('/', '\\')
        try:
            os.remove(FULL_PATH)  # after adding to safe delete the file
        except Exception as e:
            print(e)
        self.refresh()  # self.show_data()  # show data updated

    def manipulate(self, data, key):
        for index, values in enumerate(data):
            data[index] = values ^ key
        return data

    # https://www.codershubb.com/encrypt-or-decrypt-any-image-using-python/
    def encrypt(self, file_path, key):

        try:
            f = open(file_path, 'rb')
            content = f.read()
            f.close()
            bytearray_content = bytearray(content)

            # perform XOR
            self.manipulate(bytearray_content, key)

            return bytearray_content

        except:
            print("something went wrong")
            return False

    def extract_filename(self, full_path):
        return full_path[-full_path[::-1].find('/'):]

    def refresh(self):
        print("refreshing Startpage")
        self.show_data()
        self.entry_text.set('')

    def image_to_byte_array(self, image: Image):
        imageByteArr = io.BytesIO()
        image.save(imageByteArr, format=image.format)
        imageByteArr = imageByteArr.getvalue()
        return imageByteArr

    def bytes_to_image(self, data):
        stream = io.BytesIO(data)
        img = Image.open(stream)
        # img.save("jds.png")
        return img

    def preview(self, event=None):  # to preview files(image)

        t = self.remove_from_safe_helper()
        if t is None:
            return
        self.data = t[-1]
        file_name = t[1]

        if not self.preview_flag:  # if preview not supported then return from here
            # ..remove_from_safe_helper() should be executed first (as executed already here above) to set self.preview variable
            print("no preview available")
            return

        self.new_window = tk.Toplevel(self.master)
        self.new_window.title(file_name)

        # self.new_window.bind('<Escape>', self.quit)
        # https://stackoverflow.com/questions/28467285/how-do-i-bind-the-escape-key-to-close-this-window/64305769
        self.new_window.bind('<Escape>', lambda x: self.new_window.destroy())
        print("preview image")
        canvas = Canvas(self.new_window, width=400, height=300)
        canvas.grid(row=1, column=1)
        #imgg = Image.open("./enc.jpg")
        # print(type(self.image_to_byte_array(imgg)))
        # ;

        # ;
        img = self.bytes_to_image(self.data)
        img = img.resize((300, 200))
        self.img = ImageTk.PhotoImage(img)

        # https://stackoverflow.com/questions/16424091/why-does-tkinter-image-not-show-up-if-created-in-a-function
        # self.img = ImageTk.PhotoImage(
        #     Image.open("./enc.jpg").resize((300, 200)))

        # https://www.tutorialspoint.com/how-to-resize-an-image-using-tkinter

        canvas.create_image(10, 10, anchor=NW, image=self.img)
        self.new_window.focus_set()  # useful
        # canvas.update()

    # def quit(self, event=None):
    #     return self.new_window.quit()  # super().quit()


class login(tk.Frame):

    def __init__(self, parent, controller):
        self.controller = controller

        tk.Frame.__init__(self, parent)
        #self.bind('<Button-1>', self.key_pressed)

        self.initUI()

        # set focus to password_entry box to enter password directly without clicking/selecting it
        # https://stackoverflow.com/questions/22161794/tkinter-set-focus-on-entry-widget
        self.password_entry.focus_set()

    def initUI(self):  #
        label = ttk.Label(self, text="Password")
        label.grid(row=0, column=4, padx=10, pady=10)
        self.entry_text = tk.StringVar()  # type of..
        self.password_entry = tk.Entry(self, textvariable=self.entry_text)
        self.password_entry.grid(row=0, column=5)

        login_button = ttk.Button(self, text="Login",
                                  # lambda: controller.show_frame(StartPage))
                                  command=lambda: self.off_all())  # self.controller.show_frame(StartPage) if self.handle_login() else None)  # putting the button in its place   #useful: in lambda.. we need to use () caller
        # by using grid
        login_button.grid(row=1, column=1, padx=10, pady=10)
        # ;;
        self.password_entry.bind('<Return>', self.handle_login)

    def verification(self):

        # its the hash for 'saarc' hinted for testing
        password = '8ecc26875c0632bd0353919054c922530c2931c1f864973f8e5c75f7d8fc8807'
        # input_password = input("enter privacy password : ")
        # global password_entry #using it global because was unable to access password_entry ..used self.password_entry while defining in class fixed it(self keyword helped)
        input_password = self.password_entry.get()  # self.e1.get()  # self.e1.get()

        encoded = input_password.encode()
        password_hash = hashlib.sha256(encoded)
        hexdigest = password_hash.hexdigest()
        if hexdigest == password:
            print("success")
            # clear entered password  after login
            # self.entry_text.set('') #alternative
            self.password_entry.delete(0, 'end')

            return True
        else:
            print("fail")
            # login_status.config(text="failed")

    # https://stackoverflow.com/questions/64080833/how-to-disable-and-enable-all-widgets-in-a-python-tkinter-frame
    def off_all(self):
        for child in self.winfo_children():
            child.configure(state='disabled')
            self.unbind('<Return>')

    # use event=None i.e. event set to default value None to prevent ..TypeError: handle_login() missing 1 required positional argument: 'event'
    # we use event as parameter here because we have bind it with <Return> key in the password_entry box
    def handle_login(self, event=None):

        print("handle login called")
        if self.verification():
            # goto(show) start page if verified
            self.controller.show_frame(StartPage)
            self.off_all()
            # self.unbind('<Return>', self.fun)s

            # return True


class tkinterApp(tk.Tk):

    # __init__ function for class tkinterApp
    def __init__(self, *args, **kwargs):
        # __init__ function for class Tk
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("500x370")
        self.title("File SAfe")

        # creating a container
        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)

        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # initializing frames to an empty array
        self.frames = {}

        # iterating through a tuple consisting
        # of the different page layouts
        for F in (StartPage, login):

            frame = F(container, self)

            # initializing frame of that object from
            # startpage, page1, page2 respectively with
            # for loop
            self.frames[F] = frame

            frame.grid(row=0, column=0, sticky="nsew")
        self.show_frame(login)  # ;;

    # to display the current frame passed as
    # parameter
    def show_frame(self, cont):
        frame = self.frames[cont]
        frame.tkraise()


# Driver Code
app = tkinterApp()
# app.bind("<Return>", key_pressed)
app.mainloop()


#
# _________________________________________________________________________
"""

def launch_new_win():

    app = tk.Tk()
    app.geometry("600x400")
    app.title("SAFE")
    # # ,,
    # ph = tk.PhotoImage(file="images/info.png")
    # app.iconphoto(False, ph)
    # ,,
    app.configure(bg='#0D61A2')
    # disable login button of main window after lauching new window
    #   to avoid launching new window again and again..
    login_button.config(state=DISABLED)
    root.destroy()
def on_closing():
    if messagebox.askokcancel("Quit", "Do you want to quit?"):
        print("saving settings..")
        root.destroy()
def extractor():
    print("Extr")


def select_file():
    root.filename = filedialog.askopenfilename(
        initialdir='C:\\', title="Select file", filetypes=(("pdf files", "*.pdf"), ("all files", "*.*")))
    # initialdir='C:\\' for eg. sets default select dir .. here we are getting this from previously opened folder
    path_to_pdf = root.filename  # r'{}'.format(master.filename)

    # by default askopenfilename uses linux like '/' for win we have to use '\'
    # path_to_pdf = path_to_pdf.replace('/', '\\')
    # settings["initialdir"] = path_to_pdf
    entry_text.set(path_to_pdf)


# if __name__ == "__main__":
#     root = tk.Tk()
#     root.geometry("600x400")
#     root.title("File SAfe")
#     # root.configure(bg='#0D61A2')

#     photo = tk.PhotoImage(file="images/lock.png")
#     root.iconphoto(False, photo)

#     # input field for pswd
#     tk.Label(root, text="Password").grid(row=0, column=0)
#     entry_text = tk.StringVar()
#     e1 = tk.Entry(root, textvariable=entry_text)
#     e1.grid(row=0, column=1)

#     # select_file_button = tk.Button(
#     #     root, text='choose file', command=select_file)
#     # select_file_button.grid(row=0, column=2, columnspan=2,
#     #                         rowspan=2, padx=5, pady=5)

#     login_button = tk.Button(root, text="Login", command=verification)
#     login_button.grid(row=0, column=5, columnspan=2,
#                       rowspan=2, padx=5, pady=5)
#     # label for login/verify result
#     login_status = tk.Label(root, text="Status")
#     login_status.grid(row=3, column=1)

#     root.protocol("WM_DELETE_WINDOW", on_closing)
#     tk.mainloop()



'''
self keyword in class methods and variables..
--check if u are missing it and having problems

check you are applying to the correct place .. maybe trying to apply technique at wrong place
and expecting to get results at other place which is expected
maybe you're right but doing things at wrong place

command =lambda:fun() ..   can use lambda where we need to supply arguements to function
command = fun ..  otherwise we use just function name without parenthesis () to avoid calling
  function automatically ;in tkinter





'''



"""
# root = Tk()
# canvas = Canvas(root, width=300, height=300)
# canvas.pack()
# img = ImageTk.PhotoImage(Image.open("C:\\Users\\Sumit\\Downloads\\12316.jpg"))
# canvas.create_image(20, 20, anchor=NW, image=img)
