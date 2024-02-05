FROM python:3.8-slim-buster

WORKDIR /app

RUN apt-get update -y ; apt-get install -y build-essential python-dev libldap2-dev libsasl2-dev libssl-dev ; apt clean -y

COPY . .

RUN mkdir /etc/auth_api
COPY docker/main.yaml /etc/auth_api/main.yaml
COPY docker/ca.yaml /etc/auth_api/ca.yaml
COPY docker/ldap.yaml /etc/auth_api/ldap.yaml
COPY docker/maint_auth.yaml /etc/auth_api/maint_auth.yaml
COPY docker/smtp.yaml /etc/auth_api/smtp.yaml

RUN pip install poetry
RUN poetry install --no-dev

COPY docker/start-container /usr/local/bin/start-container
RUN chmod +x /usr/local/bin/start-container

ENTRYPOINT ["start-container"]
