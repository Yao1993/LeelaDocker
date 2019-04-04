call settings.bat
set BATCH_FILE_DIR=%~dp0
%BATCH_FILE_DIR%OpenSSH-Win32\ssh.exe root@%HOST_IP% -i %BATCH_FILE_DIR%\.ssh\id_rsa -p %PORT% ^
    -o UserKnownHostsFile=%BATCH_FILE_DIR%\.ssh\tmp_known_hosts "/leela_zero/src/build/leelaz  --weights /leela_zero/data/best-network.gz --gtp -t %NUM_THREADS% -r 1"