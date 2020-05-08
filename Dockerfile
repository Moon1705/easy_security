FROM ubuntu
MAINTAINER Nikita Sharaev aka moon1705

WORKDIR /project

RUN apt-get update && \
    apt-get upgrade

RUN apt-get install -y python3 && \
    apt-get install -y python3-pip && \
    pip3 install --upgrade pip

RUN apt-get install -y masscan && \
    apt-get install -y git && \
    git clone --depth=1 --branch=master https://github.com/Moon1705/easy_security.git && \
    pip3 install -r easy_security/requirements.txt && \
    apt-get clean
