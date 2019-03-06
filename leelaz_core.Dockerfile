FROM nvidia/opencl:runtime-ubuntu18.04

# RUN sed -i 's/archive.ubuntu.com/mirrors.ustc.edu.cn/g' /etc/apt/sources.list

RUN apt-get update

RUN apt-get install -y openssh-server
RUN mkdir /var/run/sshd

RUN echo 'root:root_for_leelaz' |chpasswd

RUN sed -ri 's/^#?PermitRootLogin\s+.*/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -ri 's/UsePAM yes/#UsePAM yes/g' /etc/ssh/sshd_config

RUN mkdir /root/.ssh

EXPOSE 22

CMD    ["/usr/sbin/sshd", "-D"]


# Install
RUN apt-get install -y cmake g++
RUN apt-get install -y libboost-all-dev libopenblas-dev opencl-headers ocl-icd-libopencl1 ocl-icd-opencl-dev zlib1g-dev
RUN apt-get install -y qt5-default qt5-qmake


RUN apt-get install -y git
RUN mkdir -p /leela_zero/src
RUN git clone https://github.com/leela-zero/leela-zero.git /leela_zero/src
RUN ls -a /leela_zero/src
RUN cd /leela_zero/src && git submodule update --init --recursive
RUN mkdir -p /leela_zero/src/build/

WORKDIR /leela_zero/src/build/
RUN CXX=g++ CC=gcc cmake ..
RUN cmake --build . --target leelaz --config Release -- -j4

ENV NVIDIA_VISIBLE_DEVICES all
ENV NVIDIA_DRIVER_CAPABILITIES compute,utility