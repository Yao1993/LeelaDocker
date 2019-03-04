mkdir .\.ssh\

.\OpenSSH-Win32\ssh-keygen.exe -t rsa -b 4096 -f .\.ssh\id_rsa

type .\.ssh\id_rsa.pub | .\OpenSSH-Win32\ssh.exe root@192.168.1.99 -p 32222 "cat >> ~/.ssh/authorized_keys"