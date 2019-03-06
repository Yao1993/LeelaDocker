FROM yao11/leelaz_core

RUN apt install -y curl
RUN mkdir -p /leela_zero/data
RUN cd /leela_zero/data && curl -L http://zero.sjeng.org/best-network -o best-network.gz


# CMD /leela_zero/src/build/leelaz --weights /leela_zero/data/best-network.gz --benchmark
