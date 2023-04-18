ARG VARIANT=1.17-bullseye
FROM mcr.microsoft.com/vscode/devcontainers/go:0-${VARIANT}

RUN apt-get update \
    && apt-get install -y build-essential
