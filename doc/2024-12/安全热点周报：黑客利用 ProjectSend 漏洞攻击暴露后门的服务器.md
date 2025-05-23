#  安全热点周报：黑客利用 ProjectSend 漏洞攻击暴露后门的服务器   
 奇安信 CERT   2024-12-02 09:48  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 国家能源局印发《关于加强电力安全治理 以高水平安全保障新型电力系统高质量发展的意见》</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 网站漏洞致用户信息长期被爬，两家美国保险商被罚超8100万元</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;padding: 5px 10px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 网安巨头Palo Alto全球数千防火墙被攻陷：因开发低级错误造成零日漏洞</p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.7-Zip代码执行漏洞安全风险通告**  
  
  
11月30日，奇安信CERT监测到7-Zip代码执行漏洞(CVE-2024-11477)，由于对用户提供的数据缺乏验证导致在写入内存前发生整数下溢，攻击者可能通过构造包含特制数据或压缩内容的恶意文件并诱使目标用户解压，从而执行任意代码。目前此漏洞细节和POC已在互联网公开，奇安信CERT已成功复现，建议客户尽快做好自查及防护。  
  
  
**2.ProjectSend身份认证绕过漏洞安全风险通告**  
  
  
11月28日，奇安信CERT监测到VulnCheck分配CVE-2024-11680，开源文件共享网络应用程序ProjectSend r1720之前的版本存在身份认证绕过漏洞，远程未经身份验证的攻击者可以通过向options.php发送精心设计的HTTP请求来利用此漏洞，从而在未经授权的情况下修改应用程序的配置。成功利用此漏洞后，攻击者可嵌入恶意代码、开启创建帐户功能并上传WebShell。奇安信鹰图资产测绘平台数据显示，该漏洞关联的全球风险资产总数为10068个，关联IP总数为2925个。鉴于此漏洞已发现在野利用，建议客户尽快做好自查及防护。  
  
  
**3.GitLab LFS Token权限提升漏洞安全风险通告**  
  
  
11月27日，奇安信CERT监测到官方修复GitLab LFS Token权限提升漏洞(CVE-2024-8114)，由于GitLab对LFS令牌的处理存在缺陷，使得攻击者可以利用用户的个人访问令牌（PAT）来获取LFS令牌，进而以该用户的身份执行未经授权的操作，比如读取或修改存储在LFS中的敏感文件。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为2246075个，关联IP总数为57863个。鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****Zyxel ZLD 防火墙目录遍历漏洞(CVE-2024-11667)**  
  
  
11月28日，Zyxel 防火墙的一个严重漏洞正被积极利用。该漏洞被追踪为 CVE-2024-11667，被用来部署 Helldown 勒索软件，初步报告显示至少有五个德国实体受到了攻击。  
  
CVE-2024-11667 是 Zyxel 的 ZLD 固件版本 5.00 至 5.38 中的一个目录遍历漏洞。成功利用该漏洞后，攻击者可以通过特制的 URL 执行未经授权的文件上传和下载。这可能导致敏感信息（包括系统凭据）泄露，从而导致进一步的恶意活动，例如建立恶意 VPN 连接和修改防火墙安全策略。  
  
Helldown 勒索软件于 2024 年 8 月首次被发现，似乎是从 LockBit 勒索软件构建器衍生而来的变种。这种复杂的勒索软件采用了先进的策略，包括在受感染网络内进行横向移动，以最大限度地发挥其影响力。有证据表明，如果用户凭据自首次入侵以来没有更新，即使是针对 CVE-2024-11667 进行了修补的系统也可能仍然容易受到攻击。  
  
为了缓解这一严重威胁，Zyxel 发布了 ZLD 固件版本 5.39，该版本解决了 CVE-2024-11667。   
  
  
参考链接：  
  
https://securityonline.info/cve-2024-42330-cvss-9-1-zabbix-patches-critical-remote-code-execution-vulnerability/  
  
  
**2.********ProjectSend 身份认证绕过漏洞(CVE-2024-11680)******  
  
  
11月27日，威胁行为者正在利用 ProjectSend 中一个严重的身份验证绕过漏洞的公开漏洞来上传 Webshell 并获取服务器的远程访问权限。该漏洞编号为 CVE-2024-11680，远程未经身份验证的攻击者可以通过向 options.php 发送精心设计的 HTTP 请求来利用此漏洞，从而在未经授权的情况下修改应用程序的配置。成功利用此漏洞后，攻击者可嵌入恶意代码、开启创建帐户功能并上传 webshell。  
  
虽然该漏洞已于 2023 年 5 月 16 日修复，但直至近日才被分配 CVE ，导致用户并未意识到其严重性以及应用安全更新的紧迫性。据检测到主动攻击的 VulnCheck 称，迄今为止修补速度非常慢，99% 的 ProjectSend 实例仍在运行存在漏洞的版本。  
  
ProjectSend 是一个开源文件共享网络应用程序，旨在促进服务器管理员和客户端之间的安全、私密文件传输。它是一款相当流行的应用程序，被那些喜欢自托管解决方案而不是 Google Drive 和 Dropbox 等第三方服务的组织所使用。  
  
VulnCheck 称，Censys 报告称，在线面向公众的 ProjectSend 实例大约有 4,000 个，其中大多数都存在漏洞。具体而言，研究人员报告称，基于 Shodan 数据，55% 的暴露实例运行 2022 年 10 月发布的 r1605，44% 使用 2023 年 4 月的未命名版本，只有 1% 使用修补版本 r1750。自 2024 年 9 月 Metasploit 和 Nuclei 发布 CVE-2024-11680 的公开漏洞利用以来，此类活动有所增加。  
  
VulnCheck 警告称，Webshell 存储在“upload/files”目录中，其名称由 POSIX 时间戳、用户名的 SHA1 哈希值和原始文件名/扩展名生成。通过网络服务器直接访问这些文件表明存在主动攻击行为。  
  
研究人员警告，尽快升级到 ProjectSend 版本 r1750 至关重要，因为攻击可能已经广泛传播。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-projectsend-flaw-to-backdoor-exposed-servers/  
  
  
**3.****Array Networks AG 和 vxAG ArrayOS 身份认证绕过漏洞(CVE-2023-28461)**  
  
  
11月25日，美国网络防御机构收到证据表明黑客正在积极利用 SSL VPN 产品 Array Networks AG 和 vxAG ArrayOS 中的远程代码执行漏洞。该安全问题被追踪为 CVE-2023-28461，并被分配了 9.8 的严重性评分，该机构已将其列入已知利用漏洞 (KEV) 目录中。  
  
该漏洞可通过易受攻击的 URL 利用，是一个不当的身份验证问题，允许在 Array AG 系列和 vxAG 9.4.0.481 及更早版本中执行远程代码。该漏洞于去年 3 月 9 日被披露，Array Networks 在大约一周后发布了 Array AG 9.4.0.484 版本并进行了修复。  
  
Array Networks AG 系列（硬件设备）和 vxAG 系列（虚拟设备）是 SSL VPN 产品，可提供对企业网络、企业应用程序和云服务的安全远程和移动访问。据该供应商称，它们被全球超过 5,000 个客户使用，其中包括企业、服务提供商和政府机构。  
  
CISA 尚未提供有关谁在利用该漏洞以及目标组织的任何详细信息，但“基于主动利用的证据”将其添加到已知被利用漏洞 ( KEV ) 目录中。  
  
受影响产品的安全更新可通过 Array 支持门户获取。如果无法立即安装更新，供应商还在安全公告中提供了一组命令来缓解漏洞。然而，组织应该首先测试这些命令的效果，因为它们可能会对客户端安全的功能、VPN 客户端的自动升级能力以及门户用户资源功能产生负面影响。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/hackers-exploit-critical-bug-in-array-networks-ssl-vpn-products/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.电脑遭境外黑客组织远控植入木马，重庆市一学校被罚**  
  
  
11月28日网信重庆公众号消息，重庆市北碚区网信办近日依据《中华人民共和国网络安全法》对属地一学校因未履行好网络安全保护义务做出行政处罚。经查，该学校电脑被境外黑客组织远程控制并植入木马病毒，且未采取有效防护措施切实保障网络安全，存在较大网络数据泄露的安全风险，违反《中华人民共和国网络安全法》等互联网法律法规，北碚区网信办责令该学校全面深入整改，依法对其给予警告的行政处罚。该学校负责人表示，严格按照网信部门的要求立即整改，全面深入排查存在的网络安全风险，加强互联网法律法规学习，建立完善相关制度规范，提升单位干部职工网络安全意识和应急处置技能，切实履行好网络安全保护义务。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/gSUbFWkFWAMgLBB-bU8cVg  
  
  
**2.前实习生篡改代码攻击大模型训练，字节跳动起诉索赔800万**  
  
  
11月27日AI前哨站公众号消息，字节跳动起诉前实习生田某某篡改代码攻击公司内部模型训练一案，已获北京市海淀区人民法院正式受理。字节跳动请求法院，判令田某某赔偿公司侵权损失800万元及合理支出2万元，并公开赔礼道歉。此前字节跳动11月发布内部通报指出，2024年6月至7月，集团商业产品与技术部门前实习员工田某某，因对团队资源分配不满，通过编写、篡改代码等形式恶意攻击团队研究项目的模型训练任务，造成资源损耗。今年10月，有媒体称“字节大模型训练任务被实习生攻击”，并有网传信息称“涉及8000多卡、损失上千万美元”。后字节跳动回应称确有其事，但部分内容存在夸大及失实信息。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/GyRdSUXvObc6WJy07RKZQQ  
  
  
**3.香港多名议员声称遭AI合成艳照勒索！警方称正跟进调查**  
  
  
11月27日南方都市报消息，香港立法会多名议员近日称，自己“遭人工智能合成艳照诈骗勒索”。据了解，部分议员大半年前已收到相关诈骗邮件，近日更多议员反映遭勒索。发送者在电子邮件中自称私家侦探，受人委托对议员长期跟踪调查，邮件附有疑似AI生成的议员与裸女影片截图。发送者在邮件中声称“议员已严重违纪”，要求其花钱消灾。香港保安局警务处工作人员向南都记者证实有相关案情，并表示案件已交由网络安全及科技罪案调查科跟进调查，暂未有人被拘捕。此次案件并非香港首例AI诈骗案件。今年早间，香港警方披露了一起AI换脸诈骗案，涉案金额高达2亿港元。  
  
  
原文链接：  
  
http://m.mp.oeeee.com/oe/BAAFRD0000202411271028980.html  
  
  
**4.网站漏洞致用户信息长期被爬，两家美国保险商被罚超8100万元**  
  
  
11月25日BankinfoSecurity消息，美国纽约州当局对汽车保险巨头Geico处以975万美元（约合人民币7068万元）罚款，原因是该公司未能妥善保护客户驾驶证号等信息，导致2021年初发生一系列网络安全事件。保险巨头Travelers也被处以155万美元（约合人民币1123万元）罚款，原因是黑客在2021年中利用被盗凭据窃取了驾驶证号等信息。纽约州金融服务部的调查人员发现，这两家公司都发生过黑客访问内部系统窃取未加密数据的事件，攻击者利用明文传输、API暴露、窃取管理账号等多种手法，持续爬取两家保险商线上系统的用户个人信息，并在新冠疫情期间使用窃取的驾驶证号提交了虚假的失业救济申请。该部门联合州检察总办公室通过评估确定了罚款金额。  
  
  
原文链接：  
  
https://www.bankinfosecurity.com/new-york-fines-geico-travelers-113m-for-data-breaches-a-26899  
  
  
**5.警惕攻击新型手法！俄黑客远程入侵美国企业WiFi进入内网**  
  
  
11月22日Volexity消息，美国网络安全公司Volexity曝光了一起令人震惊的网络攻击事件，俄罗斯黑客组织APT28成功突破物理攻击范围，入侵了万里之外的一家美国企业的Wi-Fi网络。2022年2月，美国首都华盛顿一家企业的WiFi网络被发现遭遇了极不寻常的攻击，这次攻击被归因于俄罗斯国家黑客组织APT28，后者过一种名为“近邻攻击”的新技术，瞄准目标企业附近建筑内的其他企业，通过渗透这些企业的网络设备和笔记本电脑进行跳板式入侵，使用暴力破解获取的有效用户凭据，远程连接了目标企业的WiFi网络并实施进一步攻击。此次事件暴露了企业WiFi网络被忽视的致命盲区和漏洞，同时也展现了APT28不断创新的攻击方式。  
  
  
原文链接：  
  
https://www.volexity.com/blog/2024/11/22/the-nearest-neighbor-attack-how-a-russian-apt-weaponized-nearby-wi-fi-networks-for-covert-access/  
  
  
**6.网安巨头Palo Alto全球数千防火墙被攻陷：因开发低级错误造成零日漏洞**  
  
  
11月19日CSO在线消息，国际网络安全巨头Palo Alto Networks日前修复了两个已被积极利用的漏洞（CVE-2024-0012、CVE-2024-9474），攻击者通过组合利用这两个零日漏洞，可实现远程完全控制PAN-OS安全设备。公司旗下搭载PAN-OS 10.2、11.0、11.1和11.2版本软件的防火墙及虚拟化安全设备均受影响。据第三方监测，自攻击活动开始以来，已有约2000台PAN-OS设备被入侵。研究人员对官方修复补丁进行逆向工程，发现这些漏洞源于开发中的低级错误。  
  
  
原文链接：  
  
https://www.csoonline.com/article/3609132/palo-alto-networks-zero-day-firewall-flaws-caused-by-basic-dev-mistakes.html  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.国家数据局《关于完善数据流通安全治理 更好促进数据要素市场化价值化的实施方案》公开征求意见**  
  
  
11月29日，国家数据局会同有关部门研究起草了《关于完善数据流通安全治理 更好促进数据要素市场化价值化的实施方案》，现公开征求意见。该文件要求到2027年底，基本构建成规则明晰、产业繁荣、多方协同的数据流通安全治理体系。该文件部署了七大主要任务，包括明晰企业数据流通安全规则、加强公共数据流通安全管理、强化个人信息流通保障、完善数据流通安全责任界定机制、加强数据流通安全技术应用、丰富数据流通安全服务供给、防范数据滥用风险。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/4SuhTPczEpenRpwL3i3paw  
  
  
**2.中共中央办公厅、国务院办公厅公布《关于数字贸易改革创新发展的意见》**  
  
  
11月28日，中共中央办公厅、国务院办公厅公布《关于数字贸易改革创新发展的意见》，要求按照创新为要、安全为基等原则，促进数字贸易改革创新发展。该文件共18条举措，其中涉及数字安全的有2条。一是促进和规范数据跨境流动。健全数据出境安全管理制度，完善相关机制程序，规范有序开展数据出境安全评估。在保障重要数据和个人信息安全的前提下，建立高效便利安全的数据跨境流动机制，促进数据跨境有序流动。二是加强数字领域安全治理。持续推动全球数字技术、产品和服务供应链开放、安全、稳定、可持续。  
  
  
原文链接：  
  
https://www.gov.cn/zhengce/202411/content_6989831.htm  
  
  
**3.七部门联合印发《推动数字金融高质量发展行动方案》**  
  
  
11月27日，中国人民银行、国家发展改革委、工业和信息化部、金融监管总局、中国证监会、国家数据局、国家外汇局等七部门联合印发《推动数字金融高质量发展行动方案》。该文件共6章23条，其中4条涉及数字安全。一是营造高效安全的支付环境。确保支付系统安全、稳定、连续运行，持续完善广泛覆盖、高效安全的现代支付体系。二是培育高质量金融数据市场。在依法安全合规前提下，支持客户识别、信贷审批、风险核查等多维数据在金融机构间共享共用和高效流通，建立健全数据安全可信共享体系。三是强化数字金融风险防范。指导金融机构加强数字金融业务合规管理，多维度开展新技术应用适配测试与安全评估，引导金融机构持续提升信息系统安全可控水平，强化模型和算法风险管理，督促金融机构加强外包风险管理。四是加强数据和网络安全防护。指导金融机构严格落实数据保护法律法规和标准规范，组织金融机构定期进行数据和网络安全风险评估，开展网络安全相关压力测试，搭建证券业数据和网络安全公共服务平台等。  
  
  
原文链接：  
  
http://www.pbc.gov.cn/goutongjiaoliu/113456/113469/5519902/index.html  
  
  
**4.国家能源局印发《关于加强电力安全治理 以高水平安全保障新型电力系统高质量发展的意见》**  
  
  
11月27日，国家能源局印发《关于加强电力安全治理 以高水平安全保障新型电力系统高质量发展的意见》。该文件共5章，包括总体要求、健全电力安全治理体系、增强电力安全治理能力、完善电力安全治理措施、提升电力安全监督管理效能。该文件多处涉及网络安全，如重点梳理涉网管理、运行控制、网络安全等与电力安全强相关的标准规范清单，在规划设计阶段针对重点地区、特殊场景合理提升设防标准；建立健全电力监控系统网络安全监测预警机制，进一步提高网络安全态势感知水平和应急处置能力；完善并网电厂涉网安全管理联席会议机制和网络安全联席会议机制。  
  
  
原文链接：  
  
http://zfxxgk.nea.gov.cn/2024-11/20/c_1310787372.htm  
  
  
**5.四部门联合印发《电信网络诈骗及其关联违法犯罪联合惩戒办法》**  
  
  
11月26日，公安部、国家发展和改革委员会、工业和信息化部、中国人民银行联合印发《电信网络诈骗及其关联违法犯罪联合惩戒办法》。该文件的惩戒对象包括因实施电信网络诈骗及其关联犯罪被追究刑事责任的人；经认定具有非法买卖、出租、出借电话卡、物联网卡、固定电话、电信线路、短信端口、银行账号、支付账户、数字人民币钱包、互联网账号等行为的单位、个人或相关组织者。该文件提出，综合运用金融惩戒、电信网络惩戒、信用惩戒等惩戒措施，同时保留被惩戒对象基本的金融、通信服务，确保满足其基本生活需要。对不同惩戒对象分别设置2年或3年的惩戒时限，对惩戒期限内多次纳入惩戒名单的，连续执行惩戒期限不得超过5年。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/dpjJRzcYT7ACpf7yJkb_Dg  
  
  
**往期精彩推荐**  
  
  
[【已复现】7-Zip 代码执行漏洞(CVE-2024-11477)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502523&idx=1&sn=a831935fa92e1ff34b2ffa0bc192aeb7&token=1318803137&lang=zh_CN&scene=21#wechat_redirect)  
[【已复现】Mozilla Firefox 释放后重用漏洞(CVE-2024-9680)安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502512&idx=1&sn=6f8aba628a7b2bfe2bcf2403541b375e&token=1318803137&lang=zh_CN&scene=21#wechat_redirect)  
  
[【在野利用】ProjectSend 身份认证绕过漏洞(CVE-2024-11680)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247502502&idx=1&sn=874d1d96ffd31643476939deced0fd4f&token=1318803137&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
  
