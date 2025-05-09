#  安全热点周报：Microsoft Power Pages 零日漏洞遭在野利用   
 奇安信 CERT   2025-02-24 09:11  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr bgless="lighten" bglessp="20%" data-bglessp="40%" data-bgless="lighten" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;background-color: rgb(254, 254, 254);font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 17px;visibility: visible;">安全资讯导视 </span></strong></span></th></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 《科学数据安全分类分级指南》等5项国家标准发布</p></td></tr><tr data-bglessp="40%" data-bgless="lighten" data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 知名交易所14亿美元数字货币被盗，损失金额创历史新高</p></td></tr><tr data-bcless="lighten" data-bclessp="40%" style="-webkit-tap-highlight-color: transparent;outline: 0px;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td align="center" valign="middle" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0px;border-style: none;border-color: initial;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">• 仿冒DeepSeek的手机木马病毒被捕获！国家病毒中心发布提醒</p></td></tr></tbody></table>  
  
  
****  
**PART****0****1**  
  
  
**新增在野利用**  
  
  
**1.****Power Pages 访问控制不当漏洞(CVE-2025-24989)**  
  
  
2月21日，微软发布了有关 Power Pages 中高危特权提升漏洞的安全公告，黑客可利用该漏洞作为零日漏洞进行攻击。该漏洞的编号为 CVE-2025-24989，是影响 Power Pages 的不当访问控制问题，它允许未经授权的行为者通过网络提升其权限并绕过用户注册控制。  
  
微软表示其已经在服务层面解决了这一风险，相应地通知了受影响的客户，并附上了如何检测潜在危害的说明。  
  
微软的安全公告称：“该漏洞已在服务中得到缓解，所有受影响的客户都已收到通知。此更新解决了注册控制绕过问题。”  
  
Microsoft Power Pages 是一个低代码、基于 SaaS 的 Web 开发平台，允许用户创建、托管和管理安全的面向外部的商业网站。它是 Microsoft Power Platform 的一部分，其中包括 Power BI、Power Apps 和 Power Automate 等工具。由于 Power Pages 是一种基于云的服务，因此可以假定攻击是远程发生的。该软件巨头尚未提供有关如何利用该漏洞进行攻击的详细信息。  
  
管理员应该检查活动日志，查找可疑操作、用户注册或未经授权的更改。由于 CVE-2025-24989 是一个权限提升漏洞，因此还应仔细检查用户列表以验证管理员和高权限用户。应进一步检查权限、安全角色、许可和网页访问控制的最新变化。立即撤销恶意账户或显示未经授权活动的账户，重置受影响的凭据，并在所有账户中实施多因素身份验证 (MFA)。  
  
   
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/microsoft-fixes-power-pages-zero-day-bug-exploited-in-attacks/  
  
  
**2.********Craft CMS 代码注入漏洞(CVE-2025-23209)******  
  
  
2月20日，美国网络安全和基础设施安全局 (CISA) 警告称，Craft CMS 远程代码执行漏洞正被利用进行攻击。  
  
该漏洞的编号为CVE-2025-23209，是一个高严重性（CVSS v3 评分：8.0）代码注入（RCE）漏洞，影响 Craft CMS 版本 4 和 5。  
  
Craft CMS 是一个内容管理系统 (CMS)，用于构建网站和定制数字体验。  
  
关于 CVE-2025-23209 的技术细节目前还不多，但利用该漏洞并不容易，因为它要求安装的安全密钥已经被破解。在 Craft CMS 中，安全密钥是一种加密密钥，用于保护用户身份验证令牌、会话 cookie、数据库值和敏感应用程序数据。  
  
CVE-2025-23209 漏洞只有在攻击者已经获得此安全密钥时才会成为问题，这为解密敏感数据、生成虚假身份验证令牌或远程注入和执行恶意代码提供了途径。  
  
该漏洞已在 Craft 5.5.8 和 4.13.8 版本中得到修复。无法立即升级到修复版本的用户建议更换安全密钥并实施严格的访问控制以降低风险。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/cisa-flags-craft-cms-code-injection-flaw-as-exploited-in-attacks/  
  
  
**3.****Palo Alto Networks PAN-OS 已认证文件读取漏洞(CVE-2025-0111)**  
  
  
2月20日，Palo Alto Networks 警告称，文件读取漏洞 (CVE-2025-0111) 目前正与另外两个漏洞 (CVE-2025-0108 和 CVE-2024-9474) 结合，在主动攻击中突破 PAN-OS 防火墙。  
  
该供应商于 2025 年 2 月 12 日首次披露了被追踪为 CVE-2025-0108 的身份验证绕过漏洞，并发布了补丁来修复该漏洞。同一天，Assetnote 研究人员发布了一个概念验证漏洞，演示了如何将 CVE-2025-0108 和 CVE-2024-9474 串联在一起，以获取未打补丁的 PAN-OS 防火墙的 root 权限。一天后，网络威胁情报公司 GreyNoise 报告称，威胁行为者已开始积极利用这些漏洞，尝试来自两个 IP 地址。  
  
CVE-2025-0111 是 PAN-OS 中的一个文件读取漏洞，允许经过身份验证的攻击者通过网络访问管理 Web 界面来读取“nobody”用户可读的文件。CVE-2025-0111 漏洞也于2025年2月12日修复，但该供应商更新了公告，警告称该漏洞现在也与其他两个漏洞一起被用在主动攻击的漏洞利用链中。  
  
更新后的公告中写道：“Palo Alto Networks 已观察到在未打补丁且不安全的 PAN-OS Web 管理界面上存在将 CVE-2025-0108 与 CVE-2024-9474 和 CVE-2025-0111 链接起来的攻击尝试。”   
  
Palo Alto Networks 敦促客户立即修补 PAN-OS Web 管理界面中的两个漏洞 - CVE-2025-0108 和 CVE-2025-0111。这些漏洞可能允许未经授权访问受影响防火墙的管理界面，从而可能导致系统入侵。在未修补和不安全的 PAN-OS Web 管理界面上，观察到针对 CVE-2025-0108 的利用尝试，该漏洞具有公开的概念验证漏洞，并将其与 CVE-2024-9474 和 CVE-2025-0111 结合起来。  
  
强烈建议拥有任何面向互联网的 PAN-OS 管理接口的客户立即采取行动以缓解这些漏洞。保护面向外部的管理接口是一项基本的安全最佳实践，建议所有组织检查其配置以最大限度地降低风险。  
  
   
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/palo-alto-networks-tags-new-firewall-bug-as-exploited-in-attacks/  
  
  
**4.********SonicOS SSLVPN 认证绕过漏洞(CVE-2024-53704)******  
  
  
2月18日，SonicWall 正在向客户发送电子邮件，敦促他们升级防火墙的 SonicOS 固件，以修补 SSL VPN 和 SSH 管理中“容易受到实际利用”的身份验证绕过漏洞。  
  
SonicWall SonicOS 在 SSLVPN 身份验证机制中包含不当身份验证漏洞，允许远程攻击者绕过身份验证。在发送给 SonicWall 客户并在 Reddit 上分享的一封电子邮件中，防火墙供应商表示补丁已发布，所有受影响的客户应立即安装以防止被攻击。  
  
至于 CVE-2024-53704，网络安全公司 Arctic Wolf 透露，在 Bishop Fox 提供概念验证 (PoC) 后不久，威胁行为者就开始利用该漏洞作为武器。  
  
鉴于漏洞正被积极利用，SonicWall 还列出了一些针对 SSLVPN 漏洞的缓解措施，包括限制对可信来源的访问以及在不需要时完全限制来自互联网的访问。为了减轻 SSH 漏洞，建议管理员限制防火墙 SSH 管理访问并考虑禁用来自互联网的访问。  
  
  
参考链接：  
  
https://thehackernews.com/2025/02/cisa-adds-palo-alto-networks-and.html  
  
  
**5.****Palo Alto Networks PAN-OS 身份验证绕过漏洞(CVE-2025-0108)**  
  
  
2月18日，攻击者正在积极利用 Palo Alto Networks PAN-OS 软件中发现的身份验证绕过漏洞，该漏洞可让未经身份验证的攻击者绕过该接口的身份验证并调用某些 PHP 脚本。  
  
2月12日由 Searchlight Cyber AssetNote 的研究人员在一篇博客文章中首次披露为零日漏洞。PAN-OS 是 Palo Alto 防火墙设备的操作系统；该漏洞影响 PAN-OS v11.2、v11.1、v10.2 和 v10.1 的某些版本，并且已针对所有受影响的版本进行了修补。该公司警告称，虽然可调用的 PHP 脚本本身不会启用远程代码执行，但利用该漏洞“可能会对 PAN-OS 的完整性和机密性产生负面影响”，可能让攻击者访问易受攻击的系统，然后利用其他漏洞实现进一步的目标。  
  
事实上，研究人员观察到攻击者在未打补丁和不安全的 PAN-OS 实例上，通过将 CVE-2025-0108 与另外两个 PAN-OS Web 管理界面漏洞（CVE-2024-9474，一个权限提升漏洞）和 CVE-2025-0111，一个经过身份验证的文件读取漏洞）结合起来，尝试进行攻击。  
  
随着受影响设备的攻击不断增加，威胁行为者显然已经意识到了漏洞利用的可能性。据 GreyNoise 的研究人员称，截至 2 月 18 日，有 25 个恶意 IP 正在积极利用 CVE-2025-0108，而在发现该漏洞的第二天，只有 2 个。根据一篇关于漏洞利用的博客文章，这些攻击最多的三个国家是美国、德国和荷兰。  
  
Palo Alto 的网络设备应用广泛，其中的漏洞经常被攻击者快速利用，因此必须尽早缓解 CVE-2025-0108 的影响。彻底消除漏洞利用风险的最佳方法是将 Palo Alto 的更新应用于受影响的设备。Palo Alto 还建议企业在管理界面中将 IP 列入白名单，以防止此类漏洞或类似漏洞在互联网上被利用。  
  
  
参考链接：  
  
https://www.darkreading.com/remote-workforce/patch-now-cisa-researchers-warn-palo-alto-flaw-exploited-wild  
  
**PART****0****2**  
  
  
**安全事件**  
  
  
**1.知名交易所14亿美元数字货币被盗，损失金额创历史新高**  
  
  
2月21日TechCrunch消息，安全内参2月22日消息，国际加密货币交易所Bybit宣布，旗下一个离线钱包遭黑客攻击，401346个以太坊被盗，价值约14亿美元。这是迄今为止最大的加密货币盗窃案，超越了此前Ronin Network和Poly Network的黑客事件，分别损失6.24亿美元和6.11亿美元。Bybit首席执行官周Ben Zhou称，黑客控制了公司一个未联网的“冷钱包”，将资金转移至在线钱包。尽管损失巨大，Bybit目前仍具有偿付能力，即使无法追回被盗资产，也能承担损失。据统计，2024年被盗加密货币的总价值约22亿美元，2023年约20亿美元。  
  
  
原文链接：  
  
https://techcrunch.com/2025/02/21/crypto-exchange-bybit-says-it-was-hacked-and-lost-around-1-4-billion/  
  
  
**2.仿冒DeepSeek的手机木马病毒被捕获！国家病毒中心发布提醒**  
  
  
2月17日央视新闻消息，国家计算机病毒应急处理中心近日在我国境内捕获发现仿冒DeepSeek官方App的安卓平台手机木马病毒。用户一旦点击运行仿冒App，该App会提示用户“需要应用程序更新”，并诱导用户点击“更新”按钮。用户点击后，会提示安装所谓的“新版”DeepSeek应用程序，实际上是包含恶意代码的子安装包，并会诱导用户授予其后台运行和使用无障碍服务的权限。该恶意App还包含拦截用户短信、窃取通讯录、窃取手机应用程序列表等侵犯公民个人隐私信息的恶意功能和阻止用户卸载的恶意行为。经分析，该恶意App为金融盗窃类手机木马病毒的新变种。国家计算机病毒应急处理中心建议，仅通过DeepSeek官方网站或正规手机应用商店下载安装相应App。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/_odF-LaYyhmh7bke2ekSNA  
  
  
**3.Palo Alto防火墙又被黑：最新漏洞披露后第二天就遭利用**  
  
  
2月14日SecurityWeek消息，美国威胁情报公司GreyNoise报告称，影响Palo Alto Networks防火墙的身份验证绕过漏洞（CVE-2025-0108）在公开披露后，短短1天内便遭到攻击者利用。Palo Alto Networks于2月12日发布了针对CVE-2025-0108的补丁和缓解措施。该漏洞允许未经身份验证的攻击者访问防火墙管理界面并执行特定的PHP脚本。GreyNoise于2月13日透露，其已开始检测到针对CVE-2025-0108的攻击尝试。截至2月14日上午，该公司已观测到来自5个不同IP地址的攻击活动。可能有多方原因造成了这一状况。一方面，该漏洞利用方式与1月披露的已被利用漏洞CVE-2025-0108类似；另一方面，有安全团队在漏洞披露后马上公布了技术细节。  
  
  
原文链接：  
  
https://www.securityweek.com/hackers-exploit-palo-alto-firewall-vulnerability-day-after-disclosure/  
  
  
**4.新一轮勒索潮来了？超级勒索软件组织宣布攻陷47家企业**  
  
  
2月13日Cybernews消息，超级勒索软件团伙Cl0p在其暗网门户发帖，公布了最新一批47家受害组织，其中大部分受害公司位于美国，其他位于加拿大、墨西哥、英国和爱尔兰等，DXC科技公司、芝加哥公立学校两家人员数量超10万的大型组织也在其中。目前相关公司尚未回应。Cl0p团伙曾犯下多起影响面超大的数据泄露事件，如MOVEit、GoAnywhere事件等。由于攻击的组织数量庞大，难以逐一接触，该组织通常不直接联系受害者，而是在暗网门户发布消息促使受害者主动联系。  
  
  
原文链接：  
  
https://cybernews.com/cybercrime/chicago-schools-dxc-technology-cl0p-ransomware/  
  
  
**PART****0****3**  
  
  
**政策法规**  
  
  
**1.两部门联合印发《全国数据资源统计调查制度》**  
  
  
2月21日，国家数据局综合司、公安部办公厅联合印发《全国数据资源统计调查制度》。该文件主要调查数据生产、存储、计算、流通、应用和安全等数据资源指标，调查频率为年报。公安部负责全国数据安全情况统计报送工作，各省、自治区、直辖市及计划单列市、新疆生产建设兵团公安厅（局）负责组织网络与信息安全信息通报机制成员单位统计、填报、审核、汇总本地区数据安全情况数据，上报公安部网络安全保卫局，公安部网络安全保卫局审核、汇总后，报送国家数据局数据资源司。  
  
  
原文链接：  
  
https://www.nda.gov.cn/sjj/zwgk/zcfb/0221/ff808081-93de5a43-0195-274a74c7-1131.pdf  
  
  
**2.《海南自由贸易港数据出境管理清单（负面清单）（2024版）》发布**  
  
  
2月20日，中共海南省委自贸港工作委员会办公室、海南省互联网信息办公室、海南省发展和改革委员会（海南省数据局）会同有关部门制定了《海南自由贸易港数据出境管理清单（负面清单）（2024 版）》，现正式印发。该文件主要针对五大重点领域进行分类管理，包括深海、航天、种业、旅游、免税商品零售业务。该文件覆盖了14个具体业务场景，针对每个场景详细规定了数据子类、基本特征与描述，同时明确了适用范围、数据定义和管理要求，构建了从资源勘探、科研监测到经营管理的全方位数据治理体系。  
  
  
原文链接：  
  
https://plan.hainan.gov.cn/sfgw/0400/202502/df645fd9512144af9e2879a7e63392ac/files/234ddff7d69a447fbe9b167311f4e02b.docx  
  
  
**3.《科学数据安全分类分级指南》等5项国家标准发布**  
  
  
2月13日，国家标准化管理委员会1月24日在官方网站发布了《中华人民共和国国家标准公告（2025年第2号）》，正式批准了《科学数据安全分类分级指南》《科学数据溯源元数据》《科学数据安全要求通则》《科学数据安全审计要求》《科学数据权益保护系列要求》等5项国家标准。该系列标准的正式发布实施，将进一步规范科学数据的管理与保护，在充分保障科学数据安全的基础上最大程度提升数据开放共享水平。遵循并实施这些标准将对《科学数据管理办法》和《数据安全法》等相关法律法规的贯彻落实产生积极影响，并将对促进科学研究的深度发展和创新活动的推进发挥至关重要的作用。  
  
  
原文链接：  
  
https://cnic.cas.cn/gzdt/202502/t20250213_7526975.html  
  
  
**4.美国会议员提出《太空基础设施法案》，将太空系统作为关基设施进行保护**  
  
  
2月10日，美国国会肯·卡尔弗特等4位两党议员联合提出了《太空基础设施法案》（H.R. 1154），要求将太空系统、服务和技术认定为关键基础设施，并采取必要措施加以保护，以确保太空资产的安全性与韧性。卡尔弗特表示：“随着我们的经济和重要通信系统愈加依赖太空系统和服务的支持，我们必须采取切实行动，增强防护以防范潜在威胁。”该法案目前已提交至美国众议院科学、太空与技术委员会审议。  
  
  
原文链接：  
  
https://calvert.house.gov/media/press-releases/rep-calvert-introduces-space-infrastructure-act  
  
  
**往期精彩推荐**  
  
  
[【已复现】Ivanti Endpoint Manager 多个信息泄露漏洞安全风险通告第二次更新](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503030&idx=1&sn=0ab060e1af22e4d3a4dac36f832ed14d&scene=21#wechat_redirect)  
[安全热点周报：苹果确认 USB 限制模式被利用进行“极其复杂的”攻击](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503019&idx=1&sn=f94d57fa239ac026a3964ddc7a23952d&scene=21#wechat_redirect)  
  
[DeepSeek引发全球关注，恶意软件鱼目混珠趁机传播](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503018&idx=1&sn=5d69c21fad271526d5e83395a9943a11&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
