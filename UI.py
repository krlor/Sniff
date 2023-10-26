import sys
import tkinter
from tkinter import  *
import io
import os
import Para

app=Tk()
app.title("SniffWriteByPHY")
app.geometry("800x600")
text_box=tkinter.Text(app)
text_box.pack()

def start_capture():
    from SniffMain import MyClass
    MyClass.mycapture_on(pattern="Intel(R) Wi-Fi 6 AX201 160MHz",callback=MyClass.packet_printer_callback)

def load_and_analysis():
    file = open("C:/Users/M/Desktop/test.txt", "r")  # 将所有数据以十六进制读入pck_list列表，并且将后面的‘\n’和前面的'0x'去掉。
    fr = file.readlines()
    pck_list = []
    analysistic=[]
    emptyfilecheck = os.path.getsize("C:/Users/M/Desktop/test.txt")
    if emptyfilecheck != 0:
        for line in fr:
            pck_list.append(line.strip())

        for i in range(len(pck_list)):
            from MODULEpacket_handler import packet_handlers
            pck_list[i] = pck_list[i][2:]
            old = sys.stdout
            new = io.StringIO()
            sys.stdout = new
            packet_handlers(pck_list[i])
            sys.stdout=old
            analysistic.append(new.getvalue())
    text_box.insert('1.0',analysistic)



# 创建一个按钮对象，并放置在窗口的下方
button1 = Button(app, text="Quit", command=app.quit)
button1.pack(side="bottom")
button2 = Button(app,text="开始抓包。",height=10,width=30,command=start_capture,bg="blue")  #启动抓包。
button2.pack(side="bottom")
button3 = Button(app,text="分析已经抓到的包",height=10,width=30,command=load_and_analysis,bg="blue") #开始分析。

button3.pack(side="top")
# 启动事件循环
app.mainloop()