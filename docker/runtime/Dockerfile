FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-dev \
    openjdk-17-jdk-headless \
    maven \
    golang-go \
    gcc g++ make \
    nodejs npm \
    curl wget git \
    net-tools iproute2 procps \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install --no-cache-dir \
    requests \
    pwntools \
    pyyaml \
    paramiko \
    httpx

WORKDIR /exp

CMD ["/bin/bash"]
