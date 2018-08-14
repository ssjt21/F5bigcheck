# -*- coding: utf-8 -*-



from Tkinter import Tk,Button,Frame,Text,Label,BOTH,W,S,E,N,StringVar,Entry
from Tkinter import Scrollbar,END
import re
from requests import get
from tkMessageBox import showinfo,showerror

import struct

from  bigico import  img
import base64

class App(object):
    def __init__(self, master):
        frame=Frame(master)
        frame.pack(fill=BOTH, expand=True)

        url_lab=Label(frame,text='URL:',fg='green',font=('Courier New',16))
        url_lab.grid(row=0,column=0,sticky=N+E)

        self.url_text = Text(frame, width=60, height=3, font=('Courier New', 12))
        self.url_text.grid(row=0, column=1)

        f5_lab=Label(frame,text='F5 Big-Ip:',fg='blue',font=('Courier New',14))
        f5_lab.grid(row=1,column=0,sticky=N)

        self.f5bigip=StringVar()
        self.f5bigipEntry=Entry(frame,textvariable=self.f5bigip)
        self.f5bigipEntry.config(font=('Courier New', 12))
        self.f5bigipEntry.config( width=60)
        self.f5bigipEntry.grid(row=1,column=1)

        self.testbtn=Button(frame,text='检测',font=('Courier New',12))
        self.testbtn.config(width=25)
        self.testbtn.config(bg='LightSkyBlue')
        self.testbtn.grid(row=2,column=1,sticky=W)

        self.decodebtn=Button(frame,text='解码F5 Big-Ip 值',font=('Courier New',12))
        self.decodebtn.config(width=25)
        self.decodebtn.config(bg='LightSkyBlue')
        self.decodebtn.grid(row=2, column=1, sticky=E)

        self.result_lab=Label(frame,text='执行结果：',fg='blue',font=('Courier New',14))
        self.result_lab.grid(row=3,column=0,sticky=N+E)

        scroll = Scrollbar(frame)
        scroll.grid(row=3,column=1,sticky=E+N+S)
        self.response=Text(frame,width=58, height=18, font=('Courier New', 12))
        self.response.grid(row=3,column=1,sticky=W+S)
        self.response.config(yscrollcommand=scroll.set)
        scroll.config(command=self.response.yview)

        self.msg = StringVar()
        self.msg_lab= Label(frame, textvariable=self.msg, fg='blue', font=('Courier New', 12))
        self.msg_lab.grid(row=4, column=0, columnspan=2, sticky=N + S + W + E)

        self.testbtn.bind('<Button-1>',self.check)
        self.decodebtn.bind('<Button-1>',self.decode_bigip2)

        self.url=''
        self.pattern = re.compile('^(?:http|https)://(?:\w+\.)+.+')

        self.headers= {

              "User-Agent":"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
            }


    def check(self, event):
        self.msg.set('')
        self.url = self.url_text.get(1.0, END).strip()
        chek_url = self.pattern.match(self.url)
        # print chek_url.group()
        if not chek_url:
            # print ('123')
            self.msg.set('请输入正确的(GET)URL!')
        else:
            try:
                self.msg.set('')
                self.f5bigip.set('')
                self.response.delete(1.0,END)
                response = get(self.url, headers=self.headers)
                headers=response.headers
                set_cookie = headers.get('Set-cookie',None)
                headers='\n'.join([ ':'.join(item) for item in response.headers.iteritems()])
                # print headers

                if set_cookie:
                    bigip_value = self.getBigIPvalue(set_cookie)
                    if bigip_value:
                        self.f5bigip.set(bigip_value)
                        self.msg_lab.config(fg='red')
                        host=self.decode_bigip(bigip_value)
                        self.msg.set('F5 BIG-IP Cookie Remote Information Disclosure\n'
                                     '存在信息泄露漏洞！\n'
                                     '内网地址：'+host)

                    else:
                        self.msg_lab.config(fg='blue')
                        self.msg.set('不存在信息泄露漏洞！')
                else:
                    self.msg_lab.config(fg='blue')
                    self.msg.set('不存在信息泄露漏洞！')




                self.response.delete(1.0, END)
                self.response.insert(END,headers+'\n\n'+ response.text)


            except:
                self.msg_lab.config(fg='red')
                self.msg.set('网络资源请求失败，请确保已经接入互联网和网址的有效性！')

    def getBigIPvalue(self,set_cookie):
        if set_cookie:
            lst=set_cookie.split(';')
            lst=[ item.split('=') for item in lst]
            # print lst
            for key ,value in lst:
                if re.search('BIGipServer.*?',key):
                    return value

        return ''
    def decode_bigip(self,bigip_value):
        if bigip_value:
            if re.match('\d+\.\d+\.\d+',bigip_value):
                host,port,end=bigip_value.split('.')
                host=[ord(i) for i in struct.pack("<I", int(host))]
                port=[ord(e) for e in struct.pack("<H",int(port))]
                host='.'.join([str(i) for i in host ])
                port='0x%02X%02X' % (port[0],port[1])
                # print port
                port=str(int(port,16))

                return ':'.join([host,port])
            else:
                showerror('Decode F5 Bigip Error',
                          'Bigip value is Not a valid value !\n (xxx.xxx.xx)(x代表数字) ')
                return ''

        return ''
    def decode_bigip2(self,event):
        bigip_value=self.f5bigip.get().strip()
        result = self.decode_bigip(bigip_value)
        if result:
            showinfo( "Decode F5 Bigip ",
                "%s : %s" % (bigip_value,result))
        else:
            showerror('Decode F5 Bigip Error',
                      'Bigip value is Not a valid value !\n (xxx.xxx.xx)(x代表数字) ')





















root=Tk()
with open('bigip.ico','wb') as f:
    f.write(base64.b64decode(img))


root.title('F5 Big-IP 信息泄露检测工具 by WD(WX:13503941314)  Topsec ')
root.geometry('722x500+100+100')
root.iconbitmap('bigip.ico')
app=App(root)
root.mainloop()




if __name__ == '__main__':
    pass