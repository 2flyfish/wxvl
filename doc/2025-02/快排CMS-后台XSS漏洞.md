#  快排CMS-后台XSS漏洞   
原创 骇客安全  骇客安全   2025-02-18 18:00  
  
## 漏洞描述  
  
快排CMS 后台存在XSS漏洞，通过后台构造特殊语句可以造成访问网站的用户被XSS影响  
  
## 漏洞影响  
```
快排 CMS <= 1.2
```  
  
## 环境搭建  
  
https://gitee.com/qingzhanwang/kpcms  
  
## 漏洞复现  
  
漏洞出现在登录后台的网站编辑的位置，由于没有对输出的字符进行过滤，导致XSS  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NCztrlE4h6tSfVex97mmxlkxpHUu2AyrHicfHcdNwdb6bznbNTN2f4icyhTsmCtf9ebrYSELIk4GpQ/640?wx_fmt=png&from=appmsg "null")  
  
  
主页版权处嵌入XSS代码  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NCztrlE4h6tSfVex97mmxlaicXoJibA9kMRDK4FYDWa34WudGfeLfUpY35LvbmKLAYtliaY8CcFmtgQ/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IePibcXn991NCztrlE4h6tSfVex97mmxliaDhsmtJrCqkSbuT1HxtSRNmq5Ndx4iaiaZutKvKe4Xicu9jsWyRh0aaOA/640?wx_fmt=png&from=appmsg "null")  
  
  
