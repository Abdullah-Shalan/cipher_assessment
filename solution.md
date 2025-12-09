# Document Control

### Candidate Name: Abdullah Alshalan
### Document Received On: 07/12/2025
### Assessment Submission Date: 09/12/2025

## Part 1: Technical Assessment
### Section 1: Automation & Data Analysis

My initial solution was to use the regex `[a-zA-Z0-9.-]+.[a-zA-Z]+` to fetch the domain names, but this regex grabbed `index.html`. Then I noticed that I can split each log entry by `"` and **only** get the domain names. Then I used shell utilities to count and filter results.

My Solution:
```bash
# !/bin/bash

WEB_LOG="../web_access.log"
BENIGN="../benign_domains.txt"

awk -F\" '{print $4}' "$WEB_LOG" > all_domains.txt

total_domains=$(cat all_domains.txt | wc -l)

sort all_domains.txt -uo all_domains.txt
sort "$BENIGN" -uo benign_sorted.txt

unique_domains=$(cat all_domains.txt | wc -l)

# fetch domains not in benign, and unique to web_access.log
comm all_domains.txt benign_sorted.txt -32 > sus_domains.txt
sus_count=$(cat sus_domains.txt | wc -l)

# fetch benign domains found in web_access.log
comm all_domains.txt benign_sorted.txt -12 > benign_found.txt
benign_count=$(cat benign_found.txt | wc -l) 
```

Output Results:
```text
= Summary Report =
- Total log entries processed : 300
- Unique domains found : 31
= Suspicious Domains =
badstuff.ru
evilserver.org
fakebanklogin.io
hackmepls.cn
malicious.net
phishingsite.co
randomdomain19.com
randomdomain23.com
randomdomain30.com
randomdomain34.com
randomdomain37.com
randomdomain44.com
randomdomain55.com
randomdomain57.com
randomdomain74.com
randomdomain79.com
randomdomain98.com
randomdomain99.com
stealyourdata.xyz
- Suspicious domains count : 19
= Benign Domains =
amazon.com
apple.com
bbc.co.uk
cnn.com
github.com
google.com
linkedin.com
microsoft.com
nytimes.com
reddit.com
stackoverflow.com
wikipedia.org
- Benign domains identified count : 12
```

## Section 2: Log Analysis

### Case #1
This activity seems suspicious for a couple of reasons, first is setting the `ExecutionPolicy` to `Bypass` which will not raise a warning when running an **untrusted** executable, possibly leading to running a malicious software without noticing. Second is using an `EncodedCommand` rather that `Plain Text`, while I see this as a less concern than the first reason it's worth to consider that an attacker would preferer to encode commands to bypass security tools. Finally, the `NoProfile` option is the cherry on top because it might let the attacker avoid system logs, which makes it harder to track-down the attack. 

### Case #2
This entry clearly shows that a threat detection system has matched a file payload with a known malicious phishing payload. This machine is compromised and actions need to be taken to mitigate damage. 

As an analyst I would:
1. Isolate the host to prevent spreading the virus
2. Collect and preserve evidence to help avoid any future attacks
3. Use the found hash to search if any other machine have been attacked
4. Remove the file and run scans to verify that the malware is gone
5. Find out how this file got here by asking if anyone clicked or opened suspicious emails

Without `CTI` this file would probably go unnoticed and blend in with other files is the system, but `CTI` gave us the information that lead us to catch this malicious file and handle it properly. `CTI` made this alert actionable by giving us the data we needed to defend against this attack.

### Case #3
What's interesting is that a the same IP address is trying to guess the admin page URL by  putting in different URLs that might be accurate, but they got a `404` meaning nothing is there, then they successfully hit endpoint `/phpmyadmin/index.php` with `200` status code. Once the admin page was found they started attempting to guess the username and password for the admin. This behavior is likely from a bot that tries to `brute force` credentials, preventive measures should be taken.  

Regex to extract passwords is `password=[^&\s]+` and testing it:

```bash
#!/bin/bash
grep -Po 'password=\K[^&\s]+' logs.txt > passwords.txt
```

Passwords.txt:
```text
popa3d
xxxxx
root
123
123456
12345678
```

## Section 3: Detection Engineering
### Rule #1

What is this rule trying to detect? Why would this behavior be suspicious?

```sql
from process where
  process.name == "powershell.exe" and
  process.command_line like "*-enc*"
```

Detects PowerShell commands that use `EncodedCommand` option, allowing attacker's to pass encoded payloads instead of plain text command. This behavior is suspicious because an admin would almost never encode a command, and command encoding is a common phishing/ransomware giveaway.

### Rule #2

What is this rule trying to detect? Why would we be alert on this behavior?

```sql
from network where
  destination.ip in (threat.indicator.ip)
```

This rule detects when a `host` attempts to connect to an `IP` that is listed in a threat intelligence `blocklist`.

We alert on this behavior because contacting a known malicious `IP` is a high indicator of compromise, and require immediate investigation.

## Section 4: Threat Context Enrichment
### Part 1: Threat Report Analysis
1. What vulnerability was exploited by the threat actor, and how was it leveraged in the attack? 
```text
The actors exploited a remote-code-execution vulnerability in on-premises Microsoft SharePoint. They used it to upload webshells to Internet-facing SharePoint servers. The webshells provided a foothold for uploading additional tools and running arbitrary commands. The vulnerability was patched by Microsoft on March 2019
```
2. What was the purpose of the tools identified as webshell, HTRAN, and Mimikatz in the attacker’s toolset? 
```text
- Webshells: act as a remote, persistent entry-point on the webserver that allows uploading files, executing commands, and staging further tools.
      
- HTRAN: a traffic-proxy, used to proxy or relay connections via intermediate hosts to hide the attacker’s origin and make relay connections harder to trace.
    
- Mimikatz: credential-dumping tool used to extract plaintext credentials, password hashes and tickets from Windows memory and stores.
```
3. Which geographies were targeted in this campaign? Mention specific countries where possible. 
```text
Unit42’s language places the victims in the Middle East region, but Unit42 intentionally does not always publicize exact victim-country names, it explicitly references Saudi Arabian NCSC advisories in this campaign.
```
4. How does the behavior of Emissary Panda reflect a sophisticated or advanced persistent threat (APT) actor?
```text
They exploited a freshly-patched RCE in public/Internet-facing infrastructure quickly after patch release. They used of custom backdoors (HyperBro), reuse of code/sideloaded DLLs with code overlap to prior campaigns.
```
5. What persistence mechanism(s) did the attacker use to maintain access? 
```text
Used Webshells on SharePoint (persist on the webserver and can be invoked repeatedly). And DLL sideloading to upload legitimate executables + malicious DLLs to gain code execution under legitimate processes.
```
6. How did the threat actor achieve lateral movement? 
```text
By credential theft to harvest credentials and reuse them across hosts. And Exploitation of internal vulnerabilities, they uploaded tools that exploit the system and move laterally where unpatched.
```
7. Identify any command-and-control infrastructure or domains mentioned. 
```text
Unit42 lists a HyperBro C2 endpoint: `hxxps://185[.]12[.]45[.]134:443/ajax` and the raw IP `185.12.45.134`. Use these as IOCs.
```
8. As a CTI analyst at Cipher, which serves regional and Saudi clients, why would this vulnerability, among the many other vulnerabilities that surface each day, be of interest to you and why should you report it? (Justify)
```text
- Internet-facing SharePoint servers are common in government/enterprise: CVE-2019-0604 is RCE and trivial to weaponize—exploitation yields immediate remote code exec and webshell installation.
    
- Regionally relevant: Unit42 correlated this campaign with advisories from Saudi Arabian NCSC.
    
- Operational risk: attackers used the foothold to perform credential theft, which can rapidly lead to domain compromise or large-scale data loss.
    
- Actionable outcome: reporting allows defenders to patch, deploy web-server integrity monitoring, and hunt for the specific IOCs.
```

### Part 2: Enrichment Script
The script code, results, and logs can be found [here]().
