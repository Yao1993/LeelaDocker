call settings.bat
.\OpenSSH-Win32\ssh.exe root@%HOST_IP% -i .\.ssh\id_rsa -p %PORT% /leela_zero/src/build/leelaz  --weights /leela_zero/data/best-network.gz --gtp -t %NUM_THREADS%