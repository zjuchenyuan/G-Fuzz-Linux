FROM zjuchenyuan/gollvm

RUN apt update &&\
    apt install -y libncurses-dev gawk flex bison openssl libssl-dev dkms libelf-dev libudev-dev libpci-dev libiberty-dev autoconf bc libmysql++-dev &&\
    pip install termcolor
    