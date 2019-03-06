 docker run -d --name='Leela-zero' \
    -p 32222:22 \
    --runtime=nvidia \
    leelaz_with_network:with_network