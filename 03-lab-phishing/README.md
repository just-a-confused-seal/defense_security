## Introduction
This lab will go through some basic on how to do analysis on email phishing.

## Lab 01 - Volatility & PGP email (FwordCTF)
Download memory dump from https://drive.google.com/file/d/1OqrNosho2yYFSu05sNKamQ1VeQcDzRVn/view, some context on the email phishing:
```
Semah was having some cryptography lessons, but while learning he encrypted his file, but since he followed the steps of his teacher, he contacted him but he admitted that he didn’t receive an answer although the teacher told him that he gave him everything he needs. So as our group, we are sending you to help him out.

Flag Format : FwordCTF{DateOfReceive_SenderUsername_contentofencrypted File}

Example :

Date : 1 March,2021 1:23 (Submit in this format : MMDDYYYY-hh:mm) [no time conversion needed]

username : semah ba

content : 123abc5649abcedf123abc5649abcedf

Flag is : FwordCTF{03012021–01:23_semah.ba_123abc5649abcedf123abc5649abcedf}

author : SemahBA
```
Dont forget to unzip the challenge file, like this:
```
~# unzip challenge.zip   
Archive:  challenge.zip
  inflating: challenge.raw  
```

1. First we need to identify the email application used by the PC. You can used the following volatility command:
```
~# python3 vol.py -f ~/Desktop/challenge.raw windows.pslist
Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished                        
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output

4       0       System  0xfa8018d41890  76      492     N/A     False   2021-08-20 15:30:36.000000 UTC  N/A     Disabled
236     4       smss.exe        0xfa8019506650  2       29      N/A     False   2021-08-20 15:30:36.000000 UTC  N/A     Disabled
308     300     csrss.exe       0xfa8019158060  8       338     0       False   2021-08-20 15:30:42.000000 UTC  N/A     Disabled
356     300     wininit.exe     0xfa8018db9840  3       76      0       False   2021-08-20 15:30:43.000000 UTC  N/A     Disabled
364     348     csrss.exe       0xfa8018dbe060  10      222     1       False   2021-08-20 15:30:43.000000 UTC  N/A     Disabled
392     348     winlogon.exe    0xfa801a179060  4       114     1       False   2021-08-20 15:30:43.000000 UTC  N/A     Disabled
452     356     services.exe    0xfa801a1b17c0  7       183     0       False   2021-08-20 15:30:45.000000 UTC  N/A     Disabled
460     356     lsass.exe       0xfa801a1b97f0  6       511     0       False   2021-08-20 15:30:45.000000 UTC  N/A     Disabled
468     356     lsm.exe 0xfa801a1c4b30  10      138     0       False   2021-08-20 15:30:45.000000 UTC  N/A     Disabled
560     452     svchost.exe     0xfa801a234b30  10      340     0       False   2021-08-20 15:30:49.000000 UTC  N/A     Disabled
624     452     svchost.exe     0xfa801a25db30  6       239     0       False   2021-08-20 15:30:50.000000 UTC  N/A     Disabled
724     452     svchost.exe     0xfa801a29bb30  20      443     0       False   2021-08-20 15:30:51.000000 UTC  N/A     Disabled
768     452     svchost.exe     0xfa801a2b3920  19      417     0       False   2021-08-20 15:30:51.000000 UTC  N/A     Disabled
792     452     svchost.exe     0xfa801a2bb660  32      908     0       False   2021-08-20 15:30:51.000000 UTC  N/A     Disabled
884     724     audiodg.exe     0xfa801a2e1b30  5       125     0       False   2021-08-20 15:30:53.000000 UTC  N/A     Disabled
964     452     svchost.exe     0xfa801a30d890  10      252     0       False   2021-08-20 15:30:55.000000 UTC  N/A     Disabled
284     452     svchost.exe     0xfa801a354b30  13      346     0       False   2021-08-20 15:30:57.000000 UTC  N/A     Disabled
1080    452     spoolsv.exe     0xfa801a3cb420  12      265     0       False   2021-08-20 15:31:01.000000 UTC  N/A     Disabled
1112    452     svchost.exe     0xfa801a38bb30  18      313     0       False   2021-08-20 15:31:01.000000 UTC  N/A     Disabled
1232    452     armsvc.exe      0xfa801a44a340  4       63      0       True    2021-08-20 15:31:03.000000 UTC  N/A     Disabled
1292    452     svchost.exe     0xfa801a4b4350  11      173     0       False   2021-08-20 15:31:05.000000 UTC  N/A     Disabled
1784    452     taskhost.exe    0xfa80198b44e0  9       174     1       False   2021-08-20 15:31:38.000000 UTC  N/A     Disabled
1856    768     dwm.exe 0xfa801a5e8b30  3       70      1       False   2021-08-20 15:31:38.000000 UTC  N/A     Disabled
1884    1848    explorer.exe    0xfa801a5f7b30  32      970     1       False   2021-08-20 15:31:39.000000 UTC  N/A     Disabled
512     1884    StikyNot.exe    0xfa80192f9b30  9       138     1       False   2021-08-20 15:31:43.000000 UTC  N/A     Disabled
832     1884    SSScheduler.ex  0xfa801a677b30  1       59      1       True    2021-08-20 15:31:44.000000 UTC  N/A     Disabled
1344    452     SearchIndexer.  0xfa801a28a060  12      645     0       False   2021-08-20 15:31:46.000000 UTC  N/A     Disabled
1704    1344    SearchProtocol  0xfa801a6cd910  6       310     0       False   2021-08-20 15:31:48.000000 UTC  N/A     Disabled
596     440     notepad.exe     0xfa8019160630  1       64      1       False   2021-08-20 15:32:29.000000 UTC  N/A     Disabled
1724    304     notepad.exe     0xfa8018e85b30  1       64      1       False   2021-08-20 15:32:58.000000 UTC  N/A     Disabled
1852    452     sppsvc.exe      0xfa80198c5870  4       141     0       False   2021-08-20 15:33:09.000000 UTC  N/A     Disabled
304     452     svchost.exe     0xfa80198c5340  13      317     0       False   2021-08-20 15:33:10.000000 UTC  N/A     Disabled
840     1800    notepad.exe     0xfa8019935b30  1       64      1       False   2021-08-20 15:33:10.000000 UTC  N/A     Disabled
992     1780    notepad.exe     0xfa801a17e060  1       64      1       False   2021-08-20 15:33:39.000000 UTC  N/A     Disabled
2164    1884    notepad.exe     0xfa801a333630  1       60      1       False   2021-08-20 15:34:24.000000 UTC  N/A     Disabled
2180    1344    SearchFilterHo  0xfa801a6e0750  4       85      0       False   2021-08-20 15:34:48.000000 UTC  N/A     Disabled
2308    560     WmiPrvSE.exe    0xfa801a351630  7       116     0       False   2021-08-20 15:35:09.000000 UTC  N/A     Disabled
2512    1884    DumpIt.exe      0xfa801a3df610  2       45      1       True    2021-08-20 15:35:16.000000 UTC  N/A     Disabled
2536    364     conhost.exe     0xfa801a3e2840  2       53      1       False   2021-08-20 15:35:16.000000 UTC  N/A     Disabled

```
At first you might think that there should be email client like thunderbird, outlook and etc. While those assumption is not wrong, but right now there is no email client in our list, the user might closed or shutdown the email client when its retrieved by forensic team.

Lets check the command line, may be we can find something interesting:
```
~# python3 vol.py -f ~/Desktop/challenge.raw windows.cmdline             
Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished                        
PID     Process Args

4       System  -
236     smss.exe        \SystemRoot\System32\smss.exe
308     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
356     wininit.exe     wininit.exe
364     csrss.exe       %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
392     winlogon.exe    winlogon.exe
452     services.exe    C:\Windows\system32\services.exe
460     lsass.exe       C:\Windows\system32\lsass.exe
468     lsm.exe C:\Windows\system32\lsm.exe
560     svchost.exe     C:\Windows\system32\svchost.exe -k DcomLaunch
624     svchost.exe     C:\Windows\system32\svchost.exe -k RPCSS
724     svchost.exe     C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
768     svchost.exe     C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
792     svchost.exe     C:\Windows\system32\svchost.exe -k netsvcs
884     audiodg.exe     C:\Windows\system32\AUDIODG.EXE 0x2d8
964     svchost.exe     C:\Windows\system32\svchost.exe -k LocalService
284     svchost.exe     C:\Windows\system32\svchost.exe -k NetworkService
1080    spoolsv.exe     C:\Windows\System32\spoolsv.exe
1112    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
1232    armsvc.exe      "C:\Program Files (x86)\Common Files\Adobe\ARM\1.0\armsvc.exe"
1292    svchost.exe     C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
1784    taskhost.exe    "taskhost.exe"
1856    dwm.exe "C:\Windows\system32\Dwm.exe"
1884    explorer.exe    C:\Windows\Explorer.EXE
512     StikyNot.exe    "C:\Windows\System32\StikyNot.exe" 
832     SSScheduler.ex  "C:\Program Files (x86)\McAfee Security Scan\3.11.1664\SSScheduler.exe" 
1344    SearchIndexer.  C:\Windows\system32\SearchIndexer.exe /Embedding
1704    SearchProtocol  "C:\Windows\system32\SearchProtocolHost.exe" Global\UsGthrFltPipeMssGthrPipe1_ Global\UsGthrCtrlFltPipeMssGthrPipe1 1 -2147483646 "Software\Microsoft\Windows Search" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; MS Search 4.0 Robot)" "C:\ProgramData\Microsoft\Search\Data\Temp\usgthrsvc" "DownLevelDaemon" 
596     notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\Downloads\Secret content\flag.txt.asc
1724    notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\INBOX
1852    sppsvc.exe      C:\Windows\system32\sppsvc.exe
304     svchost.exe     C:\Windows\System32\svchost.exe -k secsvcs
840     notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\Spam
992     notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\Trash
2164    notepad.exe     "C:\Windows\system32\notepad.exe" 
2180    SearchFilterHo  "C:\Windows\system32\SearchFilterHost.exe" 0 504 508 516 65536 512 
2308    WmiPrvSE.exe    C:\Windows\system32\wbem\wmiprvse.exe
2512    DumpIt.exe      "C:\Users\SemahAB\Downloads\DumpIt.exe" 
2536    conhost.exe     \??\C:\Windows\system32\conhost.exe

```
Ok! we can see from the above result that the user actually opening several inbox email from the email client which in this case using notepad and we also found an interesting file that was being open called flag.txt.asc. While the following analysis in terms of name and settings might not come in the real world scenario, it is crucial for investigator to have a train eye to find anything consider suspicious based on their context of investigation.
Lets try to extract those files (flag.txt.asc and INBOX), in order to extract the file we need to find memory location for each respective files, using windows.filescan plugin:
```
~# python3 vol.py -f ~/Desktop/challenge.raw windows.filescan > filescan_challenge.txt
~# cat filescan_challenge.txt| grep -i "flag"
0x7fb5d2e0      \Users\SemahAB\Downloads\Secret content\flag.txt.asc
~# cat filescan_challenge.txt| grep -i "thunderbird"
0x7e458a30      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\INBOX
0x7e5355d0      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail
0x7e55e740      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com
0x7e8b2330      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com
0x7e9b5070      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com
0x7ebfde90      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com
0x7fc74470      \Program Files\Mozilla Thunderbird\thunderbird.exe
0x7fc7a620      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\Spam
0x7fc7fca0      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com\Trash
0x7fc87070      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail
0x7fca8480      \Users\SemahAB\AppData\Roaming\Thunderbird\Profiles\gb1i6asd.default-release\ImapMail\imap.yandex.com
0x7fca8b20      \Program Files\Mozilla Thunderbird\mozglue.dll
```
Because the output of windows.filescan plugin is overwhelming, it is recommend to save the output into a temp file like above.
We found the flag.txt.asc file which located at 0x7fb5d2e0, email INBOX at 0x7e458a30 and email Spam 0x7fc7a620. Its a good practice to retrieved inbox, spam and trash so we sure that we got all the emails. 

```
~# mkdir dump_thunderbird
~# python3 vol.py -f ~/Desktop/challenge.raw -o dump_thunderbird windows.dumpfiles --physaddr 0x7fb5d2e0
Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x7fb5d2e0      flag.txt.asc    file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat
~# python3 vol.py -f ~/Desktop/challenge.raw -o dump_thunderbird windows.dumpfiles --physaddr 0x7e458a30
Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x7e458a30      INBOX   file.0x7e458a30.0xfa801a3a4690.DataSectionObject.INBOX.dat
~# python3 vol.py -f ~/Desktop/challenge.raw -o dump_thunderbird windows.dumpfiles --physaddr 0x7fc7a620
Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished                        
Cache   FileObject      FileName        Result

DataSectionObject       0x7fc7a620      Spam    file.0x7fc7a620.0xfa801a549c90.DataSectionObject.Spam.dat


```
Lets see what we found in those two files:
```
~# file file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat 
file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat: PGP message Public-Key Encrypted Session Key (old)
~# cat file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat 
-----BEGIN PGP MESSAGE-----

hQIMA6mGMG+kfeOaAQ/+K8a+2BQVT+Ixk6xJKytj0xbDUqfw7FUQuKLjWBcxddbn
hd8eKmWIswUYpV3PmluCqJE5LRkdpX3Rdu/iK2ZRNyK7fGA3R3r3KFiBn5qKj0S4
D47LqwDE/fpo5YUGt3GH6Cpujv3DrdIpXcn2yFZLBiho5415bcTn2D3qm/H6uz9N
JFzved20D05OxTjj+a4s8Jsf7eroBj7DSIvvbD5/SF85rO1u1iQQHif2Na1CyrXX
sJyAU59iVipWgjo1uoGfD8PqnhJdctnTbxu2oYY6MpnQ6K98WI6hwyo/crwUGJU1
nQ8JKEQrirmcbZLsHb1fzmLDsEf2f0prG1QJXA3a9panz3N+TvIXvoWRXLkLgOcj
KjK3NjZOlnsngcXNfaSIeZelskfCg096cUiEnfUeDDc8CaGFPO4uGnhnVo/bcEFM
AuAiegy0/avdVIOU/Ho2o3ON6cQceYlsZD/Viy6oeNSib1Iyu3FLO1ZQMiaPZ6j3
Ewrfag7mr5AOLM11WtYJRYtQh2oLV5hYsvxylxZOGdIJ05hDj/CdEcxYLQ0cv3xJ
xi4shl99rGgYL2NGALrL5pnjCBDBzAdIhKImlSZmurA+29/8iE5If+NJk86SQhNl
lhSF+jIrApsQkl0cTPoE+GPmA9QicMXeLXXB+iJjDG7MVOMX1aeJROmvGWTOxBTS
swFiIgGBQQHE4cjQh8soViVMP7tOkraCYZRYGTxlrFJiCeI38gk7hx0n0hMnfMyy
lzzAKo8Fvt69q6smjOns0MhFVIfT4bUrb0md7KMXqn/OvtP/L/S9IEKjsMvk7yl6
wrLYGYwBeIgfHqPIML0DxOuqV9WKWPoigazdRVW2hQqyEjqbJRG/GIyfaisMxNlT
O+BIdWAsM3f7+gytkvmFo4lnR+Y7yVOL618HSBhie2SFwGNu
=YEJl
-----END PGP MESSAGE-----
~# cat file.0x7e458a30.0xfa801a3a4690.DataSectionObject.INBOX.dat
....
Don't forget about the decoding part we told you by phone.

Best Regards.

--------------YtZXP7kyPtT66v0uLnfRMtYS
Content-Type: text/html; charset=UTF-8
Content-Transfer-Encoding: 7bit

<html>
  <head>

    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  </head>
  <body>
    <p>Dear SemahBa,</p>
    <p>We happily announce you that the mission has completed
      successfully and we were able to get you what you want. So now
      from your side, all you have to do is importing this and
      everything is clear to go.<br>
      <br>
      Here you go : <br>
    </p>
    <pre>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

Don't forget about the decoding part we told you by phone.

Best Regards.

</pre>
  </body>
</html>
```
Inside file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat we found the encrypted message encrypt with public key and inside file.0x7e458a30.0xfa801a3a4690.DataSectionObject.INBOX.dat we found inside the email they attached the private key to decrypt the encrypted message.
First we need to format the private key into a correct PGP private key block, you can do it like this:
1. We need to concat the private key into one line and save it into a file
2. We can used fold utility in linux to align the private key into every 64 characters.
```
~# cat key.txt| fold -w 64                                       
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
mAoM8ZdyvSFLrJAo1g==

```
In this case, the raw private key is stored key.txt and once its converted to the right format you need to save it into different files.
3. For final touch you have to surround the formatted private key with the following value:
```
-----BEGIN PGP PRIVATE KEY BLOCK-----

<base64-encoded-key-data>

-----END PGP PRIVATE KEY BLOCK-----
```
Finally we can import the private key(in this example: private.key) using gpg utility, like this:
```
gpg --import private.key                         
gpg: invalid armor header: lQdGBGEflVIBEAC2+BPGRROhzjEQ6hnKcHN+opd5lKomU8Oz/NHfZ0pS8Au3FWef\n
gpg: key CF3F0AC5B51CF5A1: "SemahBA (Not too far to get what you want) <SemahBA@fword.tech>" not changed
gpg: key CF3F0AC5B51CF5A1: secret key imported
gpg: Total number processed: 1
gpg:              unchanged: 1
gpg:       secret keys read: 1
gpg:  secret keys unchanged: 1

```
We can try to decrypt the encrypted message:
```
~# gpg --decrypt file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat 
gpg: encrypted with rsa4096 key, ID A986306FA47DE39A, created 2021-08-20
      "SemahBA (Not too far to get what you want) <SemahBA@fword.tech>"
gpg: public key decryption failed: Operation cancelled
gpg: decryption failed: Operation cancelled

```
But unfortunately the private key is protected with a password. Let's check the spam email may be there is a clue regarding the password.
```
~# cat file.0x7fc7a620.0xfa801a549c90.DataSectionObject.Spam.dat
...
Content-Type: text/plain; charset=UTF-8; format=flowed
Content-Transfer-Encoding: 7bit
Return-Path: ctf.user@yandex.com

Hello Again SemahBA,

we are sorry we forgot to send you this import thing.

But we used the same secret as your EN VAR 345YACCESSTOGENERATEP455

Best Regards.

```
As it explain above the password is stored in environment variable named 345YACCESSTOGENERATEP455, we can retrieved it using windows.envars plugin, like this:
```
~# python3 vol.py -f ~/Desktop/challenge.raw -o dump_thunderbird windows.envars | grep "345YACCESSTOGENERATEP455"
308gresscsrss.exe       0x3a1950PDB scan345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
356     wininit.exe     0x411950        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
364     csrss.exe       0x181950        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
392     winlogon.exe    0x61950 345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
452     services.exe    0x341c90        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
460     lsass.exe       0x351c90        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
468     lsm.exe 0x231c90        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
560     svchost.exe     0x1e1dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
624     svchost.exe     0x311e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
724     svchost.exe     0x1e1e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
768     svchost.exe     0x171dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
792     svchost.exe     0x301dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
964     svchost.exe     0x351e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
284     svchost.exe     0x1e1e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1080    spoolsv.exe     0x161dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1112    svchost.exe     0x361e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1232    armsvc.exe      0x151dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1292    svchost.exe     0x371e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1784    taskhost.exe    0x1c1df0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1856    dwm.exe 0x71df0 345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1884    explorer.exe    0x431e20        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
512     StikyNot.exe    0x3d1e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
832     SSScheduler.ex  0x501e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1344    SearchIndexer.  0x3c1dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1704    SearchProtocol  0x1f1e80        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
596     notepad.exe     0x2b1e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1724    notepad.exe     0x171e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
1852    sppsvc.exe      0x271e50        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
304     svchost.exe     0x1e1dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
840     notepad.exe     0x361e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
992     notepad.exe     0x221e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
2164    notepad.exe     0x301e30        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
2180    SearchFilterHo  0x2a1e80        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
2308    WmiPrvSE.exe    0x3d1dc0        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
2512    DumpIt.exe      0x81df0 345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
2536    conhost.exe     0x391950        345YACCESSTOGENERATEP455        pPaAsSpPhHrR445533
```
Finally as we found the password for the private key, lets decrypt the encrypted message again:
```
~# gpg --decrypt file.0x7fb5d2e0.0xfa801a195470.DataSectionObject.flag.txt.asc.dat
gpg: encrypted with rsa4096 key, ID A986306FA47DE39A, created 2021-08-20
      "SemahBA (Not too far to get what you want) <SemahBA@fword.tech>"
We are so proud that we sent you to give him back his important file. 

The important thing was : 23b2e901f3c3c3827a70589efd046be8

```
Reference: https://medium.com/@rifqihz/writeup-fword-ctf-2021-crypt-memory-forensic-940033a98284
