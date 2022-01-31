FROM ubuntu:trusty

WORKDIR /usr/src/app

RUN apt-get update -y
RUN apt-get install socat make gcc -y

COPY . .

RUN chmod +x run.sh

CMD ["./run.sh"]

