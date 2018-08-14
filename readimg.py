# -*- coding: utf-8 -*-

# 当前目录下进入python shell,敲入以下命令
# 1.以二进制方式打开icon.ico
# 2.进行base64编码转换
# 3.以变量形式保存在icon.py 中

import base64

open_ico=open('bigip.ico','rb')

b64str=base64.b64encode(open_ico.read())
open_ico.close()

write_data='img="%s"' %  b64str

with open('bigico.py','w') as f:
    f.write(write_data)


if __name__ == '__main__':
    pass