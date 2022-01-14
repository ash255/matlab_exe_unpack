# Title
本项目用于解析由matlab使用mcc命令编译出来的exe文件并将其转为文本文件(*.m)

## Usage
```
usage: exe2m.exe [file]\n
file: exe file path
```

## Note
1. 注释并不会被matlab编译，所以转换出来的*.m文件没有注释，在原来注释的未知留下空行
2. 源码中使用matlab key和toolbox key分别从mclmcr.dll和ctfrtcrypto.dll中获得，相关分析文件在ida文件夹下
   本人使用的matlab版本为2016Rb，并在2018Ra中通过了测试，
   但这仍然无法确定这两个key是否可以用于其他matlab版本
3. 若以上两个key无法正常工作，可以使用keyer.cpp获取其他版本的key，
   由于加载依赖的关系，必须把mclmcr.dll所在matlab路径在keyer.cpp重新设置，否则LoadLibrary将失败
4. 由于lib文件过大，使用时解压一下，见根目录下lib.zip
