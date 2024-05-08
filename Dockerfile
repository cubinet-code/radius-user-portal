# syntax=docker/dockerfile:1
FROM python:3.11-slim-buster

LABEL org.opencontainers.image.source=https://github.com/cubinet-code/radius-user-portal
LABEL org.opencontainers.image.description="Radius User Portal"
LABEL org.opencontainers.image.licenses=MIT

WORKDIR /opt/radius-user-portal
RUN chmod a+rwx /opt/radius-user-portal

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt

COPY . .

EXPOSE 8443

CMD ./run.sh
