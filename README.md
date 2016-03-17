# BigSecList
A large repository of links spanning all topics in information security.

Honeypots
---------

https://github.com/secureworks/dcept

A honeytoken-based tripwire for Microsoft's Active Directory. Honeytokens are pieces of information intentionally littered on system so they can be discovered by an intruder.

http://www.redblue.team/2015/09/using-modern-honey-network-to-detect.html

Using Modern Honey Net for honeypot deployment with Docker and Splunk integration.


Exploit Development
-------------------

https://github.com/jhaddix/tbhm/blob/master/README.md

Bug hunters methodology to help guide the exploit dev process.

http://blog.techorganic.com/2014/05/14/from-fuzzing-to-0-day/

Fuzz with immunity and peach to find a 0-day start to finish guide.

http://resources.infosecinstitute.com/intro-to-fuzzing/

Intro to fuzzing with SPIKE.

http://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/

Fuzzing start to finish with AFL

https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/

Classic 12 part series from Corelan on exploit dev from basics to fairly advanced includes some sections on ROP gadgets.

http://www.fuzzysecurity.com/tutorials.html

Lots of good stuff here on Windows and Linux exploit dev. A good alternative to Corelan with a different writing style.

http://www.securitysift.com/windows-exploit-development-part-1-basics/

Mike Czumak has a good series of articles introducing Windows exploit development. Again, it covers a lot of the same stuff as Corelan and Fuzzysecurity but he has a different writing style and may explain things better for you.

https://n0where.net/awesome-windows-exploitation-resources/ 

Awesome dump of various tools and resources for windows exploitation.

https://github.com/stephenfewer/grinder

Tool to help automate browser fuzzing and crash triage.

http://census-labs.com/media/choronzon-zeronights-2015.pdf

Good paper on fuzzing.


Social Engineering
------------------
https://khr0x40sh.wordpress.com/2014/06/02/embedding-veil-powershell-payloads-into-office-documents/

Embedding Veil obfuscated powershell meterpreter payloads into OLE files.

https://github.com/Pepitoh/VBad

Obfuscate VBA macros in OLE files for AV evasion.

http://www.labofapenetrationtester.com/2014/11/powershell-for-client-side-attacks.html

Using Nishang for various Social Engineering client side attacks.

https://github.com/samratashok/nishang

The Nishang repository for Social Engineering attacks

https://getgophish.com/

Phishing framework for social engineering attacks.



Open Threat Intelligence
------------------------

https://n0where.net/security-intelligence-collector-machinae/ 

Machinae is a tool for collecting intelligence from public sites/feeds about various security-related pieces of data: IP addresses, domain names, URLs, email addresses, file hashes and SSL fingerprints.

https://cymon.io 

Open threat intel, open APIs, and an open community have led to some exciting projects to help fight the war on cybercrime.
Cymon integration with Splunk: https://github.com/xg5-simon/Splunk_Cymon.io

https://github.com/exp0se/harbinger 

Domain/IP/Hash threat feeds checker. Will check http://ipvoid.com, http://urlvoid.com, https://cymon.io and https://virustotal.com
https://rules.emergingthreats.net/ 

Emerging threats massive free and paid database of IPS/IDS snort style rules.
https://github.com/QTek/QRadio

Threat intel aggregator from various sources similar to harbinger.

https://aptnotes.malwareconfig.com/

An attempt to collate a repository of public Cyber Security APT Reports

http://www2.fireeye.com/rs/848-DID-242/images/wp-zero-day-danger.pdf?mkt_tok=3RkMMJWWfF9wsRolv6rPd%2B%2FhmjTEU5z17O4oWKKzh4kz2EFye%2BLIHETpodcMT8ZkM7nYDBceEJhqyQJxPr3NKNgN3tx5RhPmCg%3D%3D

A Survey of Zero-Day Attacks and What They Say About the Traditional Security Model

https://www2.fireeye.com/rs/fireye/images/APT28.pdf 

A Window Intro Russia’s Cyber Espionage Operations

https://www2.fireeye.com/rs/fireye/images/rpt-apt30.pdf?mkt_tok=3RkMMJWWfF9wsRokvK7Leu%2FhmjTEU5z17ekvXaK3h4kz2EFye%2BLIHETpodcMTsRiPL%2FYDBceEJhqyQJxPr3NKNgN3tx5RhPmCg%3D%3D 

The mechanics of a long-running cyber espionage Operation

https://github.com/fireeye/iocs

More generalized collection of FireEye IOCs

https://github.com/eset/malware-ioc

ESET IOCs


Digital Forensics, Incident Response, Hunting
---------------------------------------------

https://github.com/aboutsecurity/Talks-and-Presentations/blob/master/Ismael_Valenzuela-Hunting_for_IOCs_rastrea2r-Feb-2016.pdf 

Great talk on general hunting techniques for IOCs.

https://www.youtube.com/watch?v=r9Ctji9djxI 

APT Attacks Exposed: Network, Host, Memory, and Malware Analysis. A bunch of industry pros share tips and insight in this talk.

https://github.com/Invoke-IR/PowerForensics

Power Forensics is a powershell based forensics tool for performing various incident response and forensics tasks.

https://github.com/gfoss/PSRecon

PSRecon is a powershell based initial triage and incident response tool.

https://github.com/imander/DarkObserver/blob/master/darkobserver.ps1 

Windows PowerShell domain scanning tool
Article http://seclist.us/darkobserver-windows-powershell-domain-scanning-tool.html 

http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-61r2.pdf

NIST Special Publication 800 61 revision 2 for Incident Response

http://www.sans.org/reading-room/whitepapers/incident/incident-handlers-handbook-33901

SANS Incident Handlers Handbook

https://www.fireeye.com/content/dam/fireeye-www/services/freeware/ug-redline.pdf

Redline User Guide for incident response.

https://github.com/mozilla/mig

Tool from mozilla for distributed real time incident response.

https://github.com/volatilityfoundation/volatility

Volatility memory analysis for forensics/IR

https://github.com/google/rekall

Rekall memory analysis for forensics/IR

https://github.com/google/grr

Google rapid response forensics and IR tool for enterprise scalable analysis.

https://github.com/meirwah/awesome-incident-response

Fantastic collection of IR and Forensics tools.

http://digital-forensics.sans.org/community/summits

SANS Summit related talks and presentations on IR and Forensics.


SIEM/Big Data/Analytics
-----------------------

https://gist.github.com/gfoss/2b39d680badd2cad9d82 

GFOSS’s Nefarious PowerShell Commands List

http://www.learnsplunk.com/

Great website with video and textual content to go from 0 to hero with Splunk.

http://www.redblue.team/2015/09/spotting-adversary-with-windows-event.html

Windows Event log monitoring 2 part series.

http://www.redblue.team/2016/01/powershell-traceless-threat-and-how-to.html

Detecting powershell attacks.


IPS/IDS/Networking Monitoring
-----------------------------

https://www.bro.org/documentation/index.html

Bro documentation for network monitoring

https://www.youtube.com/watch?v=Bjz2i2Q-MZY

Bro training for beginners

https://github.com/aol/moloch

Moloch is a large scale full packet capture, index, and analysis system.


Penetration Testing & Offensive Security
----------------------------------------

http://www.pentest-standard.org/index.php/Main_Page

Penetration Testing Execution Standard

https://github.com/byt3bl33d3r/MITMf

Framework for Man in the middle attacks

https://github.com/n1nj4sec/pupy

Pupy is a python based RAT


https://github.com/PowerShellEmpire/Empire

Empire is a powershell based RAT

https://github.com/PowerShellMafia/PowerSploit

Post-execution powershell offensive toolset.

http://www.pentest.guru/index.php/2015/10/19/ditch-psexec-spraywmi-is-here/

SprayWMI is an alternative to using PSEXEC to get shell on remote systems, leaves fewer forensic artifacts behind.

https://github.com/iagox86/dnscat2

DNS Exfiltration tool

https://www.vulnhub.com/

CTF Style vulnerability and exploit practice.

https://github.com/denandz/KeeFarce

Extract keepass keys from memory (2.x)

https://github.com/mogwaisec/mjet

JMX Exploitation Toolkit

http://decidedlygray.com/2015/11/19/evil-access-point-with-auto-backdooring-ftw/

Evil AP With Auto-Backdooring.

https://github.com/dotcppfile/DAws

Decent web shell

http://foxglovesecurity.com/2016/01/16/hot-potato/

Priv Esc attack.

http://beenhack3d.blogspot.ca/2011/08/generating-password-lists-and-using.html

Short article with links to a bunch of techniques used for generating password lists with Cewl and Crunch.

https://www.kickstarter.com/projects/1980078555/chameleonmini-a-versatile-nfc-card-emulator-and-mo?ref=discovery

NFC Card Emulator

https://cyberarms.wordpress.com/2015/10/04/anti-virus-bypass-with-shellter-5-1-on-kali-linux/

Shellter for AV Bypass


Malware Analysis, Reverse Engineering, Assembly, Research
---------------------------------------------------------

https://www.sans.org/reading-room/whitepapers/malicious/packer-analysis-report-debugging-unpacking-nspack-34-37-packer-33428

Analyzing binaries that have been packed.

https://github.com/Dynetics/Malfunction

Tool for function level fuzzy hashing comparison in malware analysis.

https://github.com/eset/malware-research

Some malware research from ESET

http://www.redblue.team/2016/02/a-soft-introduction-to-malware-analysis.html

Introduction to malware analysis

http://www.redblue.team/2015/09/a-primer-on-disassembling-function.html

Some introductory material to assembly language
Follow up post: http://www.redblue.team/2015/10/disassembling-loops-and-control.html

http://www.redblue.team/2015/10/solving-2015-flare-on-re-contest.html

Two part series introduction to some reverse engineering concepts and walk-through.

https://duo.com/assets/pdf/WoW64-Bypassing-EMET.pdf

EMET bypass method.

https://github.com/fireeye/flare-floss/blob/master/README.md

Automated Obfuscated String Solving

http://blog.didierstevens.com/programs/xorsearch/

Tool above is similar to this tool that Didier Stevens created for solving XOR related obfuscated strings in malicious code.


Security Assessment, Gap Analysis, Architectural Controls
---------------------------------------------------------

https://www.cisecurity.org/critical-controls/download.cfm?f=CSC-MASTER-VER%206.0%20CIS%20Critical%20Security%20Controls%2010.15.2015  

The CIS Critical Security Controls for Effective Cyber Defense

http://www.hackinsight.org/news,565.html

Defending against Mimikatz

https://github.com/mozilla/MozDef

Incident Handling platform for processing events and helping to automate handling and security related ticketing workflows.
