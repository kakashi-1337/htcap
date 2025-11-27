# HTCAP - Web Application Security Scanner for SPAs
# Updated Dockerfile for modern environments
FROM ubuntu:22.04

ARG HTCAP_VERSION=master

ENV LANG=en_US.UTF-8 \
    LANGUAGE=en_US:en \
    LC_ALL=en_US.UTF-8 \
    PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=utf-8 \
    TERM=xterm \
    DEBIAN_FRONTEND=noninteractive \
    NODE_OPTIONS="--max-old-space-size=4096"

# Set up locale
RUN echo "LANG=en_US.UTF-8" > /etc/locale.conf && \
    echo "LC_ALL=en_US.UTF-8" >> /etc/environment && \
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen

# Install base dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    locales \
    apt-utils \
    ca-certificates \
    curl \
    git \
    wget \
    python3 \
    python3-pip \
    python3-setuptools \
    python3-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN locale-gen en_US.UTF-8

# Install Node.js 20.x LTS
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Chromium dependencies for Puppeteer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxkbcommon0 \
    libxrandr2 \
    libxss1 \
    libxtst6 \
    xvfb \
    fonts-liberation \
    libappindicator3-1 \
    xdg-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR "/usr/local/share"

# Install htcap
RUN curl -Ls "https://github.com/fcavallarin/htcap/tarball/${HTCAP_VERSION}" -o htcap.tar.gz && \
    tar xzf htcap.tar.gz && \
    rm htcap.tar.gz && \
    mv fcavallarin-htcap-* htcap && \
    ln -s /usr/local/share/htcap/htcap.py /usr/local/bin/htcap && \
    chmod +x /usr/local/share/htcap/htcap.py

# Install Node.js dependencies for htcap
RUN cd htcap/core/nodejs/ && npm install

# Install SQLMap (latest stable)
RUN git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git sqlmap && \
    ln -s /usr/local/share/sqlmap/sqlmap.py /usr/local/bin/sqlmap

# Install Wapiti (latest via pip)
RUN pip3 install --no-cache-dir wapiti3

# Install additional Python dependencies for enhanced features
RUN pip3 install --no-cache-dir \
    requests \
    beautifulsoup4 \
    lxml \
    pyjwt \
    graphql-core

# Create non-root user for security
RUN useradd -m -s /bin/bash htcap && \
    chown -R htcap:htcap /usr/local/share/htcap

WORKDIR /out
VOLUME /out

# Set up entrypoint
USER htcap
ENV HOME=/home/htcap

CMD ["sh", "-c", "while true; do sleep 10; done"]
