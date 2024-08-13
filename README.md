# 前言

(这只是一个整合的demo，为了更好的免杀性能，后续会酌情开源)

对于PE头的一些变形技术都比较老了，这次的学习与实践主要是某APT样本用了这保持签名有效的技术，并且支持shellcode的隐藏与识别，可以深挖的花样感觉会很多。

利用哈希校验漏洞感染文件同时不影响签名有效性的POC，在21年就已经披露了，公开利用主要是[SigFlip](https://github.com/med0x2e/SigFlip)
这个项目。我目前造了一下轮子，老POC是一体化的loader，我实现了分离的PE修改工具。后续会持续更新进行深度的攻防对抗。

后续希望把对于PE文件的利用手法都整合到项目中，因此将项目命名为PECracker。

# 使用方法

目前实现了文件头伪装(暴力不优雅版)和证书区段数据嵌入，后续继续更新

```
.\PECracker.exe
 (                                         
 )\ )      (                   )           
(()/((     )\  (      )     ( /(   (  (    
 /(_))\  (((_) )(  ( /(  (  )\()) ))\ )(   
(_))((_) )\___(()\ )(_)) )\((_)\ /((_|()\  
| _ \ __((/ __|((_|(_)_ ((_) |(_|_))  ((_) 
|  _/ _| | (__| '_/ _` / _|| / // -_)| '_| 
|_| |___| \___|_| \__,_\__||_\_\\___||_|   
                                           
written by https://github.com/berryalen02/PECracker
Usage:
  PECracker.exe [command]

Available Commands:
  crack       针对文件头的crack
  help        Help about any command
  replace     文件头替换伪装

Flags:
  -h, --help   help for PECracker.exe
```

文件头替换

```
PECracker.exe replace extract [PE file] [output] [flags]
PECracker.exe replace [command]
```

证书区段数据嵌入

```
PECracker.exe crack inject [PeFile] [output] [ShellcodeFile] [flags]
```

# 效果

以下测试均采用最简单的msf生成的calc.bin，无混淆

![](./images/PECracker1.gif)
感染PE文件后不影响执行
![](./images/PECracker2.gif)
360和wdf无检出
![](./images/PECracker6.png)
传了几个沙箱
![](./images/PECracker3.png)
![](./images/PECracker4.png)
![](./images/PECracker5.png)

# TODO

- [x] 文件头伪装(暴力替换不优雅版)
- [x] 证书区段数据嵌入
- [ ] patch(以及自动化的探索与对抗)
- [ ] .......

# 参考

https://github.com/med0x2e/SigFlip

https://mp.weixin.qq.com/s/htc8ZTbQ23kq3TEMlkqSfA
