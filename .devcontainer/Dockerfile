# See here for image contents: https://github.com/microsoft/vscode-dev-containers/tree/v0.191.1/containers/ubuntu/.devcontainer/base.Dockerfile

# [Choice] Ubuntu version: bionic, focal
ARG VARIANT="focal"
FROM mcr.microsoft.com/vscode/devcontainers/base:0-${VARIANT}

# [Optional] Uncomment this section to install additional OS packages.
RUN apt-get update \
&& export DEBIAN_FRONTEND=noninteractive \
&& curl -sL https://deb.nodesource.com/setup_14.x | bash - \
&& apt-get -y install --no-install-recommends \
apache2 \
php \
php-mysql \
nodejs \
gcc \
g++ \
make \
curl \
&& rm -rf /var/lib/apt/lists/* \
&& npm install -D tailwindcss@latest postcss@latest autoprefixer@latest



