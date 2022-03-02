# matlab_exe_unpack
本项目用于解析由matlab使用mcc命令编译出来的exe文件并将其转为文本文件(*.m)

## Usage
```
usage: exe2m.exe [-i input] [-o output] [-a/-l] [-d]
-i: 输入文件的路径
-o: 输出文件的路径或者输出的目录
-a: 全部解密，此时-o指定输出的目录
-l: 列出所有可以被解密的文件
-d: 显示调试日志
```

## Note
1. 由于lib文件过大，使用时解压一下，见根目录下lib.zip，也可以下载crypto++自行编译
2. 支持matlab v1和v2解密
3. v1版本的signature功能未实现，该功能用防止文件被修改，其未实现不影响解密。
