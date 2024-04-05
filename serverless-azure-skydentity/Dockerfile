FROM python:3.9-slim

# 5001 is the Flask specific port
EXPOSE 5001

# Keeps Python from generating .pyc files in the container.
ENV PYTHONDONTWRITEBYTECODE=1

# Turns off buffering for easier container logging
ENV PYTHONUNBUFFERED=1

# Install Azure CLI
RUN apt-get update && apt-get install -y curl
RUN curl -sL https://aka.ms/InstallAzureCLIDeb | bash

# Install pip requirements.
COPY requirements.txt .
RUN python -m pip install -r requirements.txt

WORKDIR /app
COPY azure-client-proxy/ ./proxy
COPY skydentity/ ./skydentity
COPY setup.py .

RUN pip install -e .

# Creates a non-root user with an explicit UID and adds permission to access the /app folder.
RUN adduser -u 5678 --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

WORKDIR /app/proxy

# Provides defaults for an executing container; can be overridden with Docker CLI.
CMD exec gunicorn --bind 0.0.0.0:5001 --workers 1 --threads 4 --timeout 0 app:app
