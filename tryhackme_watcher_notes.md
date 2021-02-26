
# TryHackMe Room: Watcher
- Michael Walker, Data & Cyber, Feb 2021

## Open Ports

Intitial port scan discovered the following open ports:
- Web (80) 
- FTP (21)
- SSH (22)

Attempted anonymous login to FTP service but access was denied.

## Web Page

The webpage hosted on port 80 had a page to view posts, called post.php.

This page accepted a "post" parameter in the URL query string, eg (post,php?post=something).

With some trial and error the post.php page appeared to contain a local file injection (LFI) vulnerability.

```
http://10.10.245.148/post.php?post=../../../../etc/passwd
```

**LFT Remediation**

- https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion

    The most effective solution to eliminate file inclusion vulnerabilities is to avoid passing user-submitted input to any filesystem/framework API. If this is not possible the application can maintain an allow list of files, that may be included by the page, and then use an identifier (for example the index number) to access to the selected file. Any request containing an invalid identifier has to be rejected, in this way there is no attack surface for malicious users to manipulate the path.



## Discovered Users

Exploiting the LFI on post.php allowed for reading the /etc/password file and discovering a number of valid usernames on the system: 

- mat
- will
- toby
- ftpuser

## Discovered Hidden Files

The robots.txt file on a website tells automatic bots (eg Google, Bing etc) which files and folders are allowed to be indexed by their systems and which files and folders are not.

The issue is that the robots.txt file, which has to be publicly available, often contains the locations of sensitive files or folders.

Reading the robots.txt file for the server identified two senstive locations:

- flag_1.txt
- secret_file_do_not_read.txt

The flag_1.txt was accesible via the browser and contained the first flag.

The secret_file was not accessible via the browser directly, although could still be read by exploiting the LFI vulnerability discovered earlier.

## flag_1.txt

```
FLAG{robots_dot_text_what_is_next}
```


# Discovered Credentials: ftpuser

The secret_file was able to be read by using the following URL pattern. 
- http://10.10.x.x/post.php?post=../../../../../../var/www/html/secret_file_do_not_read.txt

The web server was running Apache which usually has a default directory for storing webpages of /var/www/html and this was used to successfully read the secret_file which contained the password for ftpuser and the location on the fileserver where uploaded files would be stored.

```
ftpuser:givemefiles777
```

These credentials allowed logging into the FTP service on port 21.

On the FTP service was:
- flag_2.txt file containing the second flag, 
- a "files" directory


## flag_2.txt
```
FLAG{ftp_you_and_me}
```

## Reverse Shell: www-data

With the ability to upload files via FTP to the server, along with the ability to read/execute those files in a browser, we can try to upload a reverse shell via FTP.

A reverse shell is a way for a target server to connect back to an attacker machine, so that an attacker can run arbitrary commands on the server.

After uploading a PHP reverse shell into the FTP files directory, I setup a socat listener on my machine, then accessed the reverse shell using the following URL pattern.

- http://10.10.x.x/post.php?post=../../../../home/ftpuser/ftp/files/php-reverse-shell.php

This triggered a connection back to my machine and allowed me to run commands directly on the target server, impersonating the www-data user which runs the Apache web-server process in this case.

## Discovered Files

After enumerating the directories of the users discovered earlier, the following interesting files were found:

- /home/toby/note.txt
- /home/toby/flag_4.txt
- /home/toby/jobs/cow.sh (cron?)

- /home/mat/flag_5.txt
- /home/mat/note.txt
- /home/mat/scripts/cmd.py
- /home/mat/scripts/will_script.py

- /home/will/flag_6.txt


There was also a subdirectory where the webpages were stored, which contained a flag_3.txt file and the third flag.

- /var/www/html/more_secrets_a9f10a


## flag_3.txt

```
FLAG{lfi_what_a_guy}
```

## Privilege Escalation: www-data -> toby

The location of the fourth flag was known (/home/toby/flag_4.txt) however this file was not readable by our current user: www-data.

Performing a "sudo -l" command discovered that the www-data user was able to impersonate user toby without requiring a password.

Running sudo -u toby bash provided us a shell with the toby user and the ability to read the flag_4.txt file and the fourth flag.

## flag_4.txt

```
FLAG{chad_lifestyle}
```

## Persistence: SSH Keys

After receiving a shell as user toby, we can upload our SSH public key from attacker machine to the home diretory of the user toby (/home/toby/.ssh/authorized_keys), allowing us to login as toby via SSH without a password.



## Privilege Escalation: toby -> mat

There is a note.txt file readable by toby that suggests that an automatic script is running at regular intervals. The note is written from mat to toby.

There is a subdirectory called "jobs" and inside it a file called "cow.sh" which performs a command to copy a file.

The cow.sh file is owned by user mat, however it is writeable by our current user toby, and assuming that it runs regularly we could potentially edit this file so that the next time it runs it will execute a command we choose impersonate the user mat.

We edit the cow.sh file to append a command to copy the authorized_keys file from toby's home direcory into mat's home directory, allowing us to login as mat via SSH without a password.

Once we can login as mat we can read the flag_5.txt file and get the fifth flag.

## flag_5.txt

```
FLAG{live_by_the_cow_die_by_the_cow}
```

## Privilege Escalation: mat -> will

There is a file in mat's home directory called cmd.py which is writeable by mat.

Another script in mat's home directory called "will_script.py" is not writeable by mat, and runs as user will.

There is a entry in the sudo file that allows mat to run the will_script.py file, impersonating will, via a python3 interpreter.

The will_script.py file makes reference to the cmd.py file that mat can write to.

Editing this cmd.py file, we can include the following code so that when mat runs the will_script.py file as will, we will get python to provide us a shell as the will user.

```
import os
os.system("/bin/bash")
```

```
will /usr/bin/python3 /home/mat/scripts/will_script.py *

```

Now when we run the following command we get a shell as will, and the ability to read flag_6.txt in will's home directory and receive the sixth flag.

```
sudo -u will /usr/bin/python3 /home/mat/scripts/will_script.py /home/mat/scripts/cmd.py

```

## flag_6.txt

```
FLAG{but_i_thought_my_script_was_secure}
```


## Privilege Escalation: will -> root

Will is a member of the adm group which provides access to log files and other maintenance features.

Discovered an /opt/backups directory which is readable by the adm group.

Inside /opt/backups is a key.b64 file, which when decoded via base64 -d command provides an RSA private key.

We can use this private key to login to the root account using:

```
ssh -i private_key_file root@localhost 
```

As root we can read the final flag.

## Root Flag

```
FLAG{who_watches_the_watchers}
```


