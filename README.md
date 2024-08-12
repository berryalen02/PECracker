# 前言

对于PE头的一些变形技术都比较老了。

利用哈希校验漏洞感染文件同时不影响签名有效性的POC，在21年就已经披露了，公开利用主要是[SigFlip](https://github.com/med0x2e/SigFlip)
这个项目。我目前造了一下轮子，后续会持续更新进行攻防对抗。（其实更多是个demo，方便诸位自定义）

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

![](./images/PECracker1.gif)
感染PE文件后不影响执行
![](./images/PECracker2.gif)

# TODO

- [x] 文件头伪装(暴力替换不优雅版)
- [x] 证书区段数据嵌入
- [ ] patch(以及自动化的探索与对抗)
- [ ] .......

# 参考

https://github.com/med0x2e/SigFlip
https://mp.weixin.qq.com/s/htc8ZTbQ23kq3TEMlkqSfA