call settings.bat

mkdir .\.ssh\

.\OpenSSH-Win32\ssh-keygen.exe -t rsa -b 4096 -f .\.ssh\id_rsa


type .\.ssh\id_rsa.pub | .\OpenSSH-Win32\ssh.exe root@%HOST_IP% -p %PORT% -o UserKnownHostsFile=.\.ssh\tmp_known_hosts "cat >> ~/.ssh/authorized_keys"