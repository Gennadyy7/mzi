FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    libjpeg-dev \
    g++ \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    Cython \
    numpy \
    pillow \
    scipy \
    setuptools \
    wheel

RUN git clone https://github.com/dwgoon/jpegio.git /tmp/jpegio \
    && cd /tmp/jpegio \
    && python setup.py build_ext --inplace \
    && pip install -e /tmp/jpegio

WORKDIR /app