FROM ubuntu:20.04

# Install dependencies
# according to docker, apt isnt stable in CLI, so use apt-get.
RUN apt-get update 
RUN apt-get install -y curl socat
RUN apt-get install -y cargo
# RUN apt-get install -y python3 python3-pip
# RUN apt-get install -y nano
RUN rm -rf /var/lib/apt/lists/*

# Initialize User
RUN mkdir -p /usr/src/pwn
WORKDIR /usr/src/pwn

COPY ./rusty_ptrs_build ./rusty_ptrs