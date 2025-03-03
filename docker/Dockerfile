FROM ubuntu:jammy-20230301
#RUN apt-get update &&\
#    apt-get install -y heaptrack &&\
#    apt-get install -y heaptrack-gui
# RUN apt-get update &&\
#    apt -y install pkg-config libfreetype6-dev libfontconfig1-dev mingw-w64
COPY echo-proxy /tmp/echo-proxy
RUN chmod go+r /tmp/echo-proxy
WORKDIR "/tmp"
ENTRYPOINT ["/tmp/echo-server","-P","4848","-T","http://127.0.0.1:8123"]
#ENTRYPOINT ["tail", "-f", "/dev/null"]