FROM ubuntu:latest

RUN apt update -y
RUN apt install -y wget unzip default-jre xz-utils android-tools-adb

COPY apk.sh /apk.sh
RUN /apk.sh init

WORKDIR /wd
ENTRYPOINT ["/apk.sh"]
