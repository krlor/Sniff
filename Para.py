import sys
import tkinter
from tkinter import  *
import io
import os


para=Tk()
para.title("Typing the number here")
para.geometry("300x100")
counting=tkinter.Entry(para)
counting.pack()
def para_to_Sniff():
    var=int(counting.get())
    return var
button0 = Button(para,text="Submmit",command=para_to_Sniff)
button0.pack(side="bottom")
button1 = Button(para,text='Quit',command=para.quit)
button1.pack(side="bottom")
para.mainloop()