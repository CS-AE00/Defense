# Defense
Ramnit SBAR
<h2>Description</h2>
Project consists of a full analysis of Ramnit malware. We start the project by analyizing a PCAP of a remote intrusion attempt. Once we see in Wireshark that there were multiple failed login attempts, we then look at the full SIEM and memory to determine what is occuring. 
<br />

<h2>Languages and Utilities Used</h2>
- <b>WireShark </b>
- <b>Splunk </b> 
- <b>Memory </b>
- <b>Disk </b>

<h2>Environments Used </h2>

- <b>Amazon WorkSpace</b>

  <h2>SBAR:</h2>

<h2>EXECUTIVE SUMMARY</h2>
Following a thorough investigation done by Boots, we have uncovered a security breach stemming from an urgent email that was distributed to a number of AT-USA employees, including CFO, P.Brand and three other employees. This email, seemingly regarding the updating of employee accounts, was malicious in nature. The commonly visited website, www[.]ciso[.]guide, led employees to a compromised website, which was identified as the source of a watering hole attack utilizing a drive-by technique. The website harbored a rig exploit kit that directed visitors to a corresponding landing page, also hosting the exploit kit. Four devices within the AT-USA network were exposed to the exploit kit landing page: LAB-Win7-01, Daniel-PC, LAB-Win10-02, and LAB-Win10-03. Out of these, only two devices suffered compromise as a result of the exploit kit: LAB-Win7-01 and Daniel-PC.
 
While payloads were dropped on LAB-Win7-01, they were not executed. Nonetheless, immediate action is crucial. We recommend quarantining this device promptly removing the payloads that were dropped on the device.  Unfortunately, Daniel-PC fell victim to the exploit kit and suffered a breach. A payload was both dropped and executed on this device. This payload contained Ramnit malware. Ramnit is a form of malware that is known to steal credentials and other sensitive information. Ramnit is an advanced form of malware that can be difficult to remove or find. However, this malware was launched using a command prompt which raises severity and suspicion of an insider job.

For future protection, we recommend mandating an employee wide policy to update software often. Outdated software can contain security vulnerabilities that malicious actors can exploit. This applies not only to operating systems but also to applications, plugins, and any other software used within the organization such as Adobe flash, Javascript, etc. Also, we recommend implementing ad blockers. Ad blockers can help prevent malicious ads from being displayed on websites. Further investigation is needed to figure out how bilo400.exe was launched in command prompt and reverse engineering would need to be done to figure out what exactly was stolen. 
 
<h2>SITUATION</h2>
P. Brand, the CFO of AT-USA, received and reported a suspicious email that appeared to originate from support@ciso[.]guide, a website frequently visited by IT staff. Upon analyzing the email, Analyst Boots took into consideration several factors. The legitimacy of ciso[.]guide, its common usage among IT staff, the absence of any email attachments, and the absence of malicious binaries on P.Brand’s device were all taken into account. Thus, Boots concluded the email was benign, with no AT-USA devices compromised.
 
<h2>BACKGROUND</h2>
The incident in question was assigned by Virgil. The original email was sent to the CFO, P. Brand, on Friday, December 29, 2017, at 20:58 (UTC). With the original email available for analysis, there is a need to  scrutinize its content, as well as the findings presented in the Situation, Background, Assessment, and Recommendation (SBAR) report completed by Analyst Boots and the Security information and event management (SIEM) logs. The primary goal is to verify Boot's findings of the email being benign and no AT-USA device being compromised using the tools above.
 
<h2>ASSESSMENT</h2>
After viewing the previous SBAR and the SIEM logs, we found that the email was not responsible for any malicious content, but the referred website did contain malicious intent. Boots originally recognized a spearphishing email attempt on P. Brand, However, there were no attachments and malicious intent on P. Brand's computer. After further investigation, we found that this email contained the potential for a watering hole attack. The email was sent to four AT-USA employees, P.Brand, S.Adams, D.Walker, and M.Land. However, between 2017-12-29 21:24 and 23:37 UTC, only three of these targeted employees, S.Adams, D.Walker, and M.Land, accessed the webpage (www[.]ciso[.]guide. However, a fourth employee, Daniel, visited the same webpage (www][.]ciso[.]guide), but he was not sent the original email.  
From here, we uncovered a drive-by attack on the commonly visited webpage, www[.]ciso[.]guide. Boots concluded that he found no compromised device. His finding was incorrect. Four devices were exposed to the threat. After visiting the manipulated webpage (www[.]ciso[.]guide, these four employees devices (LAB-Win10-02\m.land, LAB-Win10-03\d.walker, LAB-Win7-01\s.adams, Daniel-PC\Daniel) were then redirected to the Rig EK landing page (vds-cs59923[.]timeweb.ru). However, after further investigation, only two devices (LAB-Win7-01 and Daniel-PC) were successfully compromised by the Exploit kit. This was probably due to exploiting a vulnerability in Adobe Flash Player. 
Between 2017-12-29 21:25-21:47 UTC, one device (LAB-Win7-01\S.Adams) was delivered four payloads ( bilo439.exe, bilo467.exe,bilo161.exe, and bilo494.exe), but none of these payloads were executed. Due to the payloads not executing, this device remained uninfected by the malware. However, at 2017-12-29 23:05 UTC, Daniel-PC\Daniel had a single payload delivered (bilo400.exe). The malware, Ramnit banking trojan infected the device from the payload at 2017-12-29 23:14 UTC.Two minutes after the Ramnit malware was executed, it established persistence on Daniel-PC. The Ramnit malware created four copies of itself on the device (inwqbuvx.exe, obomnhdf.exe, fghkroxg.exe, and xwgrttjl.exe).The devices initially connected to the Ramnit C2 server (ckkxyupextanlvcrdig[.]com) at 2017-12-29 23:16 UTC. The last successful connection to the Ramnit C2 server (ckkxyupextanlvcrdig[.]com) occurred at 2018-01-02 05:39 UTC. The device attempted one last connection attempt, but this was unsuccessful at 2018-01-04 16:40 UTC.
After more investigation, we found that there were two profiles infected by the Ramnit malware on Daniel-PC (Daniel-PC\Daniel and Daniel-PC\Waxwing).
The analysis of memory revealed the execution tree of the original bilo400.exe file, which was the initial point of compromise. Understanding how this file was executed is crucial for tracing the attack's origin. It appears that the attacker disguised their malicious actions as part of the legitimate explorer.exe process. This could be done to evade suspicion, as explorer.exe is a critical Windows process.The use of cmd.exe to launch the bilo400.exe payload is a significant finding. This suggests that the attacker had a deep understanding of the system and knew how to execute the payload using a command prompt. Such knowledge might indicate insider involvement, as it goes beyond typical exploit kit capabilities.Insiders often have privileged access and knowledge of the system's inner workings, making it easier for them to carry out targeted attacks. Additionally, legal and HR departments may need to be involved in the investigation to handle any potential employment-related actions and to ensure compliance with relevant regulations and laws.
The malware employed several persistence mechanisms to ensure it remained active on the system by targeting the Windows operating system and making multiple copies of the malware. These tactics are typical of malware to maintain control over the compromised system even after reboots.The malware dropped a copy of itself named obommhdf.exe on the system. Additionally, it spawned another copy of Ramnit, xwgrttjl.exe. Ramnit used explorer.exe to hook into the system, and it leveraged chrome.exe to utilize the "man-in-the-browser" technique. This technique allowed the malware to intercept and manipulate web traffic in real-time, potentially capturing sensitive information entered by users while browsing. The mention of copying code to other browsers indicates that the attack may have affected multiple web browsers.The copy xwgrttjl.exe was responsible for creating svchost.exe hosts that communicated with the Ramnit command and control (C2) server. This suggests that the attackers had a means of actively controlling the compromised system and exfiltrating data or receiving commands.The malware used sdbinst.exe for silent installations and tracert.exe to gain access to the system, demonstrating a level of sophistication in the attack. Attackers often leverage legitimate system utilities to evade detection. After further investigation, evidence pointed to at least eight copies of the Ramnit malware on the system. This suggests that the malware had deeply embedded itself within the system's infrastructure.
The investigation of the hard disk revealed evidence of eleven copies of the Ramnit malware on the system between 2017-12-29 23:15:03 UTC and 2018-01-02 04:19:15 UTC (see technical appendix (Sheet:Ramnit Incident)).This extensive number of copies indicates that the malware had deeply embedded itself within the system and likely carried out various malicious activities.On top of the ramnit executables, we found evidence of ramnit modules between 2017-12-29 23:16:32 UTC and 2018-01-04 16:40:31 UTC. (see technical appendix (Sheet:Ramnit Incident)). These modules are components that the malware uses to carry out specific functions, such as data exfiltration or further compromise of the system. Identifying these modules can help understand the full extent of the malware's capabilities and activities. In the hard disk, we were able to locate prefetch files that are associated with the malware Ramnit.The finding of these prefetch files provides additional evidence for the malware execution.These modifications may have been part of the malware's persistence mechanisms or efforts to evade detection (see technical appendix (Sheet:Ramnit Incident)).
During 23:15:03 the Ramnit malware created and modified registry keys to evade detection. The attackers modified several registry keys to evade detection and enhance their control over the system. These modifications included disabling firewall, Windows Defender, antivirus overrides, and other security-related settings. This is a common tactic used by malware to weaken the system's defenses.
More investigation from a reverse engineer is needed to see what information was stolen. This incident went from a lower stake incident to a higher one due to the potential insider job. 



<h2>RECOMMENDATION</h2>
In order to prevent an attack like this from occurring and perform triage on the devices, the company should:
Mandate an employee wide policy to use updated software and update computers every month. As seen by this investigation, updated computers were not compromised by the malware.
Regular Software Updates: Outdated software can contain security vulnerabilities that malicious actors can exploit. By mandating regular software updates, you ensure that your systems are equipped with the latest security patches and improvements. This applies not only to operating systems but also to applications, plugins, and any other software used within the organization.


- <b>Implementing Ad Blockers: Ad blockers can help prevent malicious ads from being displayed on websites. Malvertising (malicious advertising) can lead to drive-by downloads and other forms of cyberattacks. Ad blockers can also reduce the risk of accidentally clicking on a malicious ad or landing on a compromised website.


- <b>Employee Training and Awareness: Educate employees about the importance of cybersecurity practices. Make sure they understand the risks associated with clicking on unknown links, downloading attachments from suspicious sources, and sharing sensitive information.


- <b>Encourage employees to be mindful of social engineering attacks such as phishing and install a security solution on your devices.  


Boot's original finding needs to be revised to reflect my new findings.
Be notified of the compromise and to not visit the http referrer www[.]ciso[.]guide.
The users of Daniel-PC and LAB-Win7-01 need to be notified of the breach in the devices. The users of Daniel-PC, Daniel and Waxwing need to be informed that they have a serious malware on their computer and questioned on what could potentially be of value on the device.
Daniel should be further questioned of his potential involvement in the execution of the malware.Daniel was an active user when bilo400.exe was executed using command prompt.
Users of Daniel-PC, Daniel and Waxwing, will need to have credentials reset.
Quarantine two of the four devices involved.
Only two devices were compromised by the rig exploit kit.
LAB-Win7-01 should be immediately quarantined to removed payload dropped files(bilo439.exe, bilo467.exe,bilo161.exe, and bilo494.exe) that were not executed.
Look and fix into why the snort alerts for the malware were missed.
There were 2161 log events relating to the malware alerts in snort, but they were all undetected.
Reverse engineer the files, modules and malware to see what was accessed and what credentials were stolen.
Legal and HR departments may need to be involved in the investigation to handle any potential employment-related actions and to ensure compliance with relevant regulations and laws.

 
<h2>TECHNICAL APPENDIX</h2>
Devices impacted
<LAB-Win10-03>(10.5.10.128);\<m.land>(m.land@at-usa.co): The employee was targeted by the email but interacted with the rig exploit kit landing page, but wasn't exposed to the malware or payloads
<LAB-Win10-02>(10.5.10.127);\<d.walker>(d.walker@at-usa.co):The employee was targeted by the email but  interacted with the rig exploit kit landing page, but wasn't exposed to the malware or payloads
<LAB-Win7-01> (10.5.10.129 );\ <s.adams>(s.adams@at-usa.co): The employee was targeted by the email but interacted with the rig exploit kit landing page. The employee was exposed and compromised by the Rig Ek . The payloads (bilo467[,]exe,bilo161[.]exe, bilo494[.]exe, and bilo439[.]exe were never executed
<Daniel-PC > (10.5.10.130, 10.5.10.132, 10.5.10.133);\ <daniel>(daniel@at-usa.co)<waxwing>(waxwing@at-usa.co) :The employee was not  targeted by the email but interacted with the rig exploit kit landing page. The employee was exposed and compromised by Ramnit malware; dropped payloads (bilo400[.]exe
External hosts
<vds-cs59923[.]timeweb.ru>(176[.]57[.]214[.]103) : Contains Rig exploit kit landing page. Upon further investigation, the encoded Uri came from Russia.
<ckkxyupextanlvcrdig[.]com> (194[.]87[.]109[.]183): Host of the Ramnit C2 sever
 www[.]ciso[.]guide (35[.]196[.]138[.]220): the webpage associated with the watering hole used in the attack.

Encoded URI for Rig EK
/?MjY4NzM0&zFgggRTovMMcmVwb3J0ZnpMc2dOYnJUTnZRY2FwaXRhbA==&CfrFHAL=bG9jYXRlZA==&ESyyTsE=ZGVub21pbmF0aW9ucw==&UQlqALxy=Y2FwaXRhbA==&cXJAzhGr=dW5rbm93bg==&gRGwPutcuh=cmVwb3J0&gh23mXN32dfg3=CwjBeJKgBjlYlZUV0U9qD_iUDUnEedg8KK_kSMYA4W_sOXErEz2ln2nbQkeMMixB6E6lETi-lL&cTRfaa=Y2FwaXRhbA==&YcbDwOaLaVB=YXR0YWNrcw==&TaTfmVdWv=Y2FwaXRhbA==&WnZNVgRfBEtMx=c3Rvcm1lZA==&giwjCD=YXR0YWNrcw==&JzhYRaHphq=cmVwb3J0&CjffGT=ZGVub21pbmF0aW9ucw==&L5sdmX1Zfhds=xX_QMvWfbRXQDp3EKvncT6NHMVHRGECL2YqdmrHSefjaelWkzrfFTF_3ozKATgSG6_dtdfJSDQ&NYPnxuuEBlxdW5rbm93bg=

Malicious hash
SHA256=08875F1B26F8CDAA139402559D6716DBA973C8F9449DECB19343FBF24A58D11F,
IMPHASH=60EF23FF4838FCCE4F25B7B7F3FDE894

Ramnit in SIEM in splunk
index="sysmon" EventCode=11 dvc="Daniel-PC" Image="C:\\Users\\Daniel\\AppData\\Local\\Temp\\bilo400[.]exe"
index="sysmon" EventCode=11 dvc="Daniel-PC"| rare limit=20 Image
index="sysmon" EventCode=1 dvc="Daniel-PC" bilo400[.]exe
"daniel-pc" dvc="Daniel-PC" app="C:\\Windows\\SysWOW64\\svchost.exe" EventCode=11
OboMmhdf Image="C:\\Users\\Daniel\\AppData\\Local\\guwayhtr\\obommhdf[.]exe"
Ramnit process execution tree found in SIEM in Splunk
index="sysmon" Computer="Daniel-PC" bilo400.exe ProcessId=2148 ParentImage="C:\\Windows\\System32\\cmd.exe"
index="sysmon" Computer="Daniel-PC" obommhdf.exe ProcessId=3764
index="sysmon" Computer="Daniel-PC" obommhdf.exe ParentProcessId=492
index="sysmon" Computer="Daniel-PC" obommhdf.exe ProcessId=3804
index="sysmon" Computer="Daniel-PC" obommhdf.exe ProcessId=2292
index="sysmon" Computer="Daniel-PC" obommhdf.exe ProcessId=2756
index="sysmon" Computer="Daniel-PC" obommhdf.exe ProcessId=2756 ParentProcessId=2376
index="sysmon" Computer="Daniel-PC" sdbinst.exe
index="sysmon" Computer="Daniel-PC" tracert.exe
index="sysmon" Computer="Daniel-PC" svchost.exe| rare limit=20 ProcessId
index="sysmon" Computer="Daniel-PC" svchost.exe ParentImage="C:\\Users\\Daniel\\AppData\\Local\\Temp\\xwgrttjl.exe"
index="sysmon" Computer="Daniel-PC" svchost.exe ParentImage="C:\\Windows\\SysWOW64\\svchost.exe" ProcessId=1800

Ramnit registry changes in SIEM in Splunk
index="sysmon" EventCode=12 AND 13 dvc="Daniel-PC" | table

IOC’s, Registry,Timeline, Ramnit Execution Tree (Sheet:Ramnit Incident)

<https://docs.google.com/spreadsheets/u/0/d/1fbtOgLUBZOhswEFhBzOkJ1MNIConWL7Lm30w8odvNvI/edit>











