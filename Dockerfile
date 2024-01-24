FROM python:3.8-slim-buster

WORKDIR /app

COPY . .
RUN pip install poetry
RUN poetry install --no-dev

COPY docker/start-container /usr/local/bin/start-container
RUN chmod +x /usr/local/bin/start-container

ENTRYPOINT ["start-container"]
