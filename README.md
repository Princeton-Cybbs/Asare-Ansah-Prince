# INTERNAL PENETRATION TESTING #
INTERNSHIP REPORT 1  

    NAME: ASARE PRINCE ANSAH

    PROGRAM: TELECOMMUNICATIONS ENGINEERING

    YEAR: THREE (3)  

    TUTOR: SOMUAH  

    COMAPANY: VIRTUAL INFOSEC AFRICA (VIA) 

    PERIOD: 2ND TO 27TH SEPTEMBER, 2024

## **TABLE OF CONTENTS** ## 

+ Host Discovery
    + scope 
    + reviews 
  
+ Service discovery and port scanning
    + scope 
    + reviews 
  
+ Vulnerability Scanning
    + scope
    + reviews 
  
+ Web based attack surfaces
    + scope 
    + reviews 
  
+ Payload Generation 
    + scope
    + reviews

### **HOST DISCOVERY** ###
### **Explanation** ###
It refers to the process of identifying which hosts (computers or devices) are active and responsive on a network. When performing penetration testing, this is often the first step before proceeding with more detailed scans. Host discovery allows you to find out which systems are up and which are down, helping to narrow the focus for further analysis.

### Ping scan   
  - ***command = nmap -sn 10.10.10.0/24***
  
![alt text](<Screenshot from 2024-09-14 16-32-35.png>)

### List scan  
  - ***command nmap -sL 10.10.10.0/24***    

![alt text](<Screenshot from 2024-09-14 11-54-03.png>)

The command lists all the hosts in the 10.10.10.0/24 network without sending any packets to them. This is a non-intrusive way to quickly identify active hosts on the network.
below is the screenshot of the command and the result yielded  

### **Host Reconnaissance** ###
1. Perform the host discovery again and save the output in a grepable format to a file.
   - *command = nmap -sL 10.10.10.0/24 -oG hosts_up.txt*
  
  ![alt text](<Screenshot from 2024-09-14 12-38-06.png>)

2. Filter for the ip addresses of hosts that are up and channel it to a new file.  
    -   *command = grep -i "nmap report for" | awk '{print $5}' > live_hosts.txt*
  
  ![alt text](<Screenshot from 2024-09-14 12-41-21.png>)
   
3. Verify the contents of the new file by viewing it with the ***cat*** command.  
     - *command = cat live_hosts.txt*
  
  ![alt text](<Screenshot from 2024-09-14 12-41-43.png>)
   
4. Perform a detailed scan on the discovered hosts for more information (host reconnaissance)
     - *command = nmap -p 1-100 -sV -iL live_hosts.txt -oN detailed_scan.txt*
  
  ![alt text](<Screenshot from 2024-09-14 12-44-03.png>)

5. Analyze the results.

### **AIODNSBRUTE** ###  
It is a Python library that provides an asynchronous DNS brute-force attack tool. It allows you to efficiently enumerate subdomains of a target domain by attempting to resolve them using DNS queries.

![alt text](<Screenshot from 2024-09-14 13-43-29.png>)  

Three subdomains were found after bruteforcing the domain virtualinfosecafrica.  
    
  | Subdomain                      | Ip address     |
  | -----------                    | ------------   |
  | 1. ftp.virtualinfosecafrica.com   | 192.185.23.171 |
  | 2. whm.virtualinfosecafrica.com   | 192.185.23.171 |
  | 3. www.virtualinfosecafrica.com   | 192.185.23.171 |
|||

##  **SERVICE DISCOVERY and PORT SCANNING** ##  
### 

**PORT SWEEP**  
    Helps identify which ports are open on a target system. Each port may represent a different service or application running on the server.    
   - *command = nmap --top-ports 100 10.10.10.0*
  
  ![alt text](<Screenshot from 2024-09-14 15-34-54.png>)

**SERVICE DISCOVERY**  
   Once open ports are identified, service discovery determines what services or applications are running on those ports. This can reveal information about the software versions and configurations.  
 -  *command = nmap -sV 10.10.10.0 -oG scan_results.gnmap*
  
  ![alt text](<Screenshot from 2024-09-14 16-03-20.png>)
  

**IMPORTANCE**  
|||
|:----------------| :---------------|
| Vulnerability Identification | Knowing which services are running and their versions can help identify vulnerabilities|
| Attack Surface Analysis| By discovering open ports and services, security professionals can assess the attack surface of a system.|
| Asset Inventory | Service discovery and port scanning help create a detailed inventory of networked devices and services.|
| Topology Understanding| Helps in understanding the network’s topology and how different services are distributed across systems. This can be useful for optimizing network performance and security.|
|Configuration Review| Ensures that services are configured according to best practices and compliance requirements.|
|Detect Unauthorized Services|Port scanning can reveal unauthorized or unexpected services running on the network, which could indicate a breach or misconfiguration.|
|Investigate Incidents| In case of a security incident, understanding the services and ports involved can help in diagnosing and responding to the issue effectively.|
|Resource Utilization| Identifying services and their associated ports helps in understanding resource utilization and optimizing network performance.|
|Capacity Planning| Helps in planning for capacity and scaling by understanding the load and demands on different services.|
|||

**SEPARATION OF SERVICE DISCOVERY INTO REPECTIVE PROTOCOLS**  

COMMANDS  
1. Service scan: nmap -sV 10.10.10.0/24 -oG scan_results.gnmap
   
2. Grep TCP protocol: grep '/tcp' scan_results.gnmap > tcp_ports.txt
   
3.  Grep UDP protocol: grep '/udp' scan_results.gnmap > udp_ports.txt
   
4. View results in the grepped files: 
   - cat tcp_ports.txt
  
   - cat udp_ports.txt
5. Print specific columns:
   - awk '/ \ /tcp/ {print $2, $4}' scan_results.gnmap > tcp_ports_summary.txt
  
   - awk '/ \ /udp/ {print $2, $4}' scan_results.gnmap > udp_ports_summary.txt

*NOTE:*   
The services (https, http, vnc, telnet, mysql, rdp,smtp, ssl,netbios-ssn and microsoft-ds) were all grouped under the tcp ports. 


## MITRE CVE DATABASE ##

### Apache Limitation: Incomplete fix of CVE-2021-41773 ###

**Description**  
It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

  
  **Solution**  
  Updating Apache HTTP Server to version 2.4.51 or later is the recommended solution.

  **Victims**  
10.10.10.2,10.10.10.30, 10.10.10.45, 10.10.10.55



### **Apache Limitation: Null pointer dereference in h2 fuzzing**

**Desription**  
While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected during HTTP/2 request processing, allowing an external source to DoS the server.   

The problem of "null pointer dereference in h2 fuzzing" typically arises when the fuzzing process encounters an unexpected input that causes the H2 server to attempt to access a memory location that is not allocated or has been deallocated. This can lead to crashes, unexpected behavior, or potential security vulnerabilities.

**Solution**  
* improved input validation
* defeensive programming techniques
* code review and testing

**Victims**  
10.10.10.2,10.10.10.30, 10.10.10.45, 10.10.10.55


### Limitation: MySQL Server DDL Privilege Escalation Vulnerability

**Description**  
Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DDL). Supported versions that are affected are 5.6.49 and prior, 5.7.31 and prior and 8.0.21 and prior. Difficult to exploit vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS 3.1 Base Score 4.4 (Availability impacts). CVSS Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H).

CVSS
|score|severity|version|vector string|
|--------|--------|--------|--------|
|4.4|medium|3.1|CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:N/A:H|
||||

**Solution**
* network segmentaion
* upgrade to a patched version 

**Victims**
10.10.10.5, 10.10.10.40



### Limitation: SQL Denial of Service

**Description**  
The MySQL Server product of Oracle (versions 5.6.49 and prior, 5.7.31 and prior, and 8.0.21 and prior) has a vulnerability in its Optimizer component that allows a highly privileged attacker with network access to exploit the server. This vulnerability could lead to a Denial of Service (DoS) attack, causing the MySQL server to hang or crash repeatedly. The Common Vulnerability Scoring System (CVSS) rates this vulnerability as a 4.9, indicating a medium-severity impact, particularly affecting system availability.


CVSS 

|score|severity|version|vector string|
|--------|--------|--------|--------|
|4.9|medium|3.1|CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:N/A:H|
||||

**Solution**
* update to the latest version
* restrict neetwork access
* strenghten access control
* monitor for suspicious activity

**Victims**  
10.10.10.5, 10.10.10.40


### RealVNC Limitaion: Local privilege escalation

**Description**
The vulnerability in **RealVNC VNC Server (before version 6.11.0)** and **VNC Viewer (before version 6.22.826)** on Windows allows local privilege escalation through the MSI installer’s Repair mode. This flaw enables a local attacker to gain elevated privileges on the system, potentially leading to unauthorized actions or system control. The issue can be exploited by users with limited access, allowing them to escalate privileges and compromise system security. 

No CVSS provided

**Solution**
* Updating to the latest versions of VNC Server and Viewer is recommended.
* restriction of local user privileges
* disable msi repair mide if not needed

**Victims**  
10.10.10.10


### Microsoft Terminal Services Limitation: Local Code Execution Vulnerability

**Description**  
A vulnerability in Microsoft Terminal Server occurs when the **Start program at logon** and **Override settings from user profile and Client Connection Manager wizard** options are enabled. This configuration allows local users to force an Explorer error, which can be exploited to execute arbitrary code. Though these options were designed for user convenience, they can unintentionally provide a means for attackers to bypass intended restrictions and compromise the system.

NO CVSS

**Solution**  
* diable start program at logon
* apply principle of least privilege
* apply patches and updates

**Victims**  
10.10.10.11, 10.10.10.31, 10.10.10.60

### Limitation 2: Elevation of Privilege 

**Description**  
A vulnerability exists in **Microsoft Windows when Folder Redirection** is enabled via Group Policy, particularly when the folder redirection file server is co-located with a Terminal Server. An attacker could exploit this vulnerability by creating a new folder under the Folder Redirection root path and setting up a junction. When a new user logs in, the system redirects their personal data to this malicious folder, allowing the attacker to gain unauthorized access to sensitive files. This issue requires reconfiguring Folder Redirection and setting strict permissions, as it cannot be fixed with a security update.

CVSS

|score|severity|version|vector string|
|--------|--------|--------|--------|
|7.8|High|3.1|CCVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O/RC:C|
||||

**Solution**  
* Reconfigure folder redirection with offline files
* restrict permissions on the folder redirection root path
* separate file servers from terminal servers

**Victim**   
10.10.10.11, 10.10.10.31, 10.10.10.60

**References**  
[https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2021-26887]()



### Exim Limitation: SMTP Smuggling

**Description**  
In Exim versions prior to 4.97.1, there is a vulnerability related to SMTP smuggling in specific PIPELINING/CHUNKING configurations. This issue arises because Exim accepts a certain character sequence (<LF>.<CR><LF>), which some other email servers do not. Attackers can exploit this vulnerability to inject emails with spoofed sender addresses, thereby bypassing the Sender Policy Framework (SPF) protection that prevents email spoofing. The vulnerability can allow unauthorized mail to be accepted and delivered by vulnerable mail servers.

NO CVSS provided

**Solution**  
* upgrade to the latest version of Exim
* Disable pipelining/chunking
* Ensure proper SPF configuration

**Victims**  
10.10.10.15

**References**  
[https://sec-consult.com/blog/detail/smtp-smuggling-spoofing-e-mails-worldwide/]()

### Limitation 2: Exim DNSDB Out-of-Bounds Read Information Disclosure

**Description**  
An **information disclosure vulnerability** exists in Exim, a mail transfer agent, due to an out-of-bounds read error in the DNSDB component. This vulnerability allows network-adjacent attackers to disclose sensitive information without authentication. The flaw is in the SMTP service, which listens on TCP port 25 by default. Improper validation of user-supplied data causes the service to read beyond the allocated buffer. While this vulnerability can expose sensitive data, it can also be leveraged with other vulnerabilities to execute arbitrary code under the service account.

CVSS 

|score|severity|version|vector string|
|--------|--------|--------|--------|
|3.1|Low|3.0|CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N|
||||

**Solution**  
* Update to latest version
* Restrict access to tcp port 25
* Harden the mail server configuration
* Monitor for abnormal activity
* Apply security patches from Exim

**Victims**  
10.10.10.15

**References**  
[https://www.zerodayinitiative.com/advisories/ZDI-23-1473/]()

 
### BSD telnetd Limitation: Sensitive Environment Variable Exposure

**Description**  
A vulnerability exists in certain BSD-based Telnet clients, including those on Solaris and SuSE Linux, where remote malicious Telnet servers can exploit the NEW-ENVIRON option using the SEND ENV_USERVAR command. This allows the attacker to read sensitive environment variables, potentially exposing confidential information such as user credentials or system configurations. The vulnerability arises from improper handling of environment variables during Telnet sessions.

NO CVSS

**Solution**
* Disable Telnet and use secure alternatives
* Apply security patches
* Restrict access to Telnet 
* Monitor for malicious activity

**Victims**  
10.10.10.20

**References**  
* [http://lists.apple.com/archives/security-announce/2006//Aug/msg00000.html]()
* [http://www.redhat.com/support/errata/RHSA-2005-504.html]()
* [http://securitytracker.com/id?1014203]()


### Limitation 2: RCE via Buffer Ovrflow

**Description**  
 buffer overflow vulnerability exists in the BSD-based Telnet daemon (telnetd) across various operating systems. The flaw occurs when the telrcv function improperly handles specific telnet options, including the "AYT (Are You There)" command. This vulnerability allows remote attackers to overflow the buffer and execute arbitrary commands on the affected system, potentially leading to system compromise.

 NO CVSS provided

 **Solution**
 * Disable Telnet and use secure alternatives
* Apply security patches
* Restrict access to Telnet 
* Monitor for malicious activity

**Victims**   
10.10.10.20

**References**  
* [http://distro.conectiva.com.br/atualizacoes/?id=a&anuncio=000413]()
* [http://www.linux-mandrake.com/en/security/2001/MDKSA-2001-068.php3]()
* [http://ftp.support.compaq.com/patches/.new/html/SSRT0745U.shtml]()

### QUALITY SEVERITY RATING

CVSS v3.X Rating

|Severity|Score range|
|--------|-------------|
|None*|0.0|
|Low|0.1 - 3.9|
|Medium|4.0 - 6.9|
|High|7.0 - 8.9|
|Critical|9.0 - 10.0|

## EXPLOITDB ##
   
**Apache httpd 2.4.49**    
It is an http service version type

**Limitation**  
 Path traversal and remote code execution

![alt text](<Screenshot from 2024-09-15 22-33-19.png>)

**Victims**  
10.10.10.2,10.10.10.30, 10.10.10.45, 10.10.10.55

**solution**  
  Updating Apache HTTP Server to version 2.4.51 or later is the recommended solution.

**MySQL 5.6.49**  

**Limitation 1**  
User Privilege Escalation

![alt text](<Screenshot from 2024-09-15 22-35-16.png>)

**Victims**
10.10.10.5, 10.10.10.40

**Solution**
* network segmentaion
* upgrade to a patched version 
 
**Limitation 2**   
Local Credentials Disclosure

![alt text](<Screenshot from 2024-09-15 22-35-48.png>)

**Victims**  
10.10.10.5, 10.10.10.40

**Solution**  
* Strong password policies
* Regular patching
* Audit logging 
* Secure remote access
 
**Limitation**  
Remote Denial of Service

**Victims**  
10.10.10.5, 10.10.10.40

**Solution**  
* Server upgrade
* Configure MySQL settings
* Hardware and software optimization
* Use of commercial DoS protection services

**Microsoft Terminal Services**

**Limitation**  
Use after free

![alt text](<Screenshot from 2024-09-15 22-37-36.png>)

**Victims**  
10.10.10.11

**Solution**  
* Upgrade to patch versions
* Apply workarounds
* Implement best security practices


**Ultra VNC 1.2.4.0**  

**Limitation**  
VNC server DoS

![alt text](<Screenshot from 2024-09-15 22-39-51.png>)

**Victims**  
10.10.10.50

**Solution**  
* Patch upgrade
* Disable VNC
* Restrict VNC
* Use strong password

## **Vulnerability Scanning** ##  
## Vulnerability Scanning with Metasploit Auxiliary Module: Focusing on MySQL, VNC, RDP, and SMB

**Metasploit** is a powerful penetration testing framework that can be used to identify and exploit vulnerabilities in various services and applications. When assessing the security of a network, it's essential to conduct vulnerability scanning to identify potential weaknesses that could be exploited by malicious actors.

### MySQL Vulnerability Scanning

* **Bruteforcing:** Metasploit offers tools like `msfconsole` to launch brute-force attacks against MySQL servers. By trying various combinations of usernames and passwords, you can attempt to gain unauthorized access.
  
* **SQL Injection:** Look for vulnerabilities like SQL injection, which can allow attackers to execute arbitrary SQL commands. Metasploit has modules specifically designed for SQL injection testing.

![alt text](<Screenshot from 2024-09-15 23-53-57.png>)



### VNC Vulnerability Scanning

* **Weak Credentials:** VNC servers can be vulnerable to brute-force attacks if they have weak or default credentials. Metasploit can be used to launch brute-force attacks against VNC.
  
* **Unauthorized Access:** Ensure that VNC access is restricted to authorized users and that appropriate security measures are in place to prevent unauthorized access.

![alt text](<Screenshot from 2024-09-15 23-57-03.png>)

### RDP Vulnerability Scanning

* **Bruteforcing:** RDP servers are often targeted by brute-force attacks. Metasploit can be used to launch these attacks and attempt to gain unauthorized access.
  
* **Credential Stuffing:** Be aware of credential stuffing attacks, where attackers use stolen credentials from other breaches to attempt to log in to RDP servers.
  
* **Weak Encryption:** Ensure that RDP is configured to use strong encryption protocols to protect against man-in-the-middle attacks.

### SMB Vulnerability Scanning

* **EternalBlue:** Metasploit has modules for exploiting vulnerabilities like EternalBlue, which have been used in ransomware attacks.
  
* **SMB Relay:** Be aware of SMB relay attacks, which can be used to gain unauthorized access to network resources.
  
* **SMB Signing:** Ensure that SMB signing is enabled to protect against spoofing attacks.

![alt text](<Screenshot from 2024-09-16 00-04-07.png>)


## Creating a Custom Wordlist Using Cewl

Cewl (Custom Word List generator) is a tool that extracts words from web pages to create a custom wordlist. This can be particularly useful in penetration testing and security assessments, where specific, target-related terms can significantly enhance the effectiveness of attacks such as password cracking or brute-force attacks.

***COMMAND: cewl -m 5 -w custom_passlists.txt --with-numbers -c -v https://www.virtualinfosecafrica.com***

![alt text](<Screenshot from 2024-09-16 00-39-49.png>)

![alt text](<Screenshot from 2024-09-16 00-40-14.png>)

## Situations When a Custom Wordlist is Needed:

**Password Cracking:**  
* Target-Specific Attacks   
  When performing password cracking against a target's system or application, using a custom wordlist tailored to the target's context (e.g., company names, product names) can be more effective than generic wordlists.

* Brute-Force Attacks  
        
    Customized Attacks: For brute-forcingauthentication services (e.g., SSH, FTP), a custom wordlist that includes potential usernames and passwords specific to the target can yield better results.

**Social Engineering:**
* Phishing Campaigns  

  If you are conducting a social engineering attack, having a wordlist that includes names of employees, departments, or internal jargon can help craft more convincing phishing emails or messages.

**Security Assessments:**
* Penetration Testing  

   During penetration testing, generating a custom wordlist from a company's website can uncover security issues such as weak passwords or predictable patterns that are specific to the organization.

* Internal Network Testing
 
   When testing internal network tools or systems, a custom wordlist can help in discovering weak or default credentials that are relevant to the internal environment.

## WEB-BASED ATTACK SURFACES ##

**EyeWitness** is a tool used to automate the process of gathering information about web services by taking screenshots of websites, identifying default credentials, and providing quick access to web application metadata. It's particularly useful for penetration testers, security analysts, and researchers when assessing web applications across multiple hosts.

### Features:
- **Screenshots**: Captures screenshots of websites, which helps in quickly reviewing exposed web services.
- **Web Application Scanning**: Focuses on web services and supports both HTTP and HTTPS.
- **Metadata Collection**: Gathers information such as HTTP headers and title pages to give insights into the services running.
- **Handling Non-Standard Ports**: EyeWitness can handle web servers running on non-standard ports, which is common in internal networks.
- **Report Generation**: Generates HTML-based reports that include the screenshots and metadata for easy review.

![alt text](<Screenshot from 2024-09-16 01-37-37.png>)


## Payload Generation ##

***Java Payload***  
I will use the command below to generate the payload and later drop it on the apache tomcat webserver in order to get a shell bind .

**Command:** 
msfvenom -p java/jsp_shell_bind_tcp LPORT=4444 -f raw > bind_shell.jsp

![alt text](<Screenshot from 2024-09-16 01-54-08.png>)


***Python Payload***  
1. Generate a reverse shell payload that will be encoded in base64.  
   * Reverse shell bind command  

   * Encode python oayload to base64
   
2. Send the base64 payload to the Python server running on the target host 10.10.10.30.
   
3. Decode and execute the payload on the server.
   
4. Connect to the shell using the Netcat tool.

## Payloads Folder ##  

![alt text](<Screenshot from 2024-09-16 02-08-55.png>)

