FROM ubuntu:22.04

ENV PYTHONUNBUFFERED 1
RUN apt update && apt -y install python3-pip libpq-dev python3-dev
WORKDIR /root
COPY requirements.txt /root
RUN pip3 install --no-cache-dir -r requirements.txt
RUN useradd nonroot
RUN mkdir /usr/src/app; chown nonroot:nonroot /usr/src/app
USER nonroot
WORKDIR /usr/src/app
COPY --chown=nonroot:nonroot otau_mgmt_backend ./
RUN python3 manage.py collectstatic --noinput

EXPOSE 8001
CMD openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout myproject.key -out myproject.crt -subj "/C=IN/ST=GUJARAT/L=AHMEDABAD/O=haidar/OU=DEV/CN=task/emailAddress=admin@admin.com"; python3 manage.py migrate --noinput
