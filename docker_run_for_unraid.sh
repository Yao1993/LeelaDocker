 docker run -d --name='Leela-zero' \
    --net='bridge' -e TZ="Asia/Shanghai" -e HOST_OS="Unraid" \
    -p 32222:22 \
    --runtime=nvidia \
    leelaz_with_network:with_network