# syntax=docker/dockerfile:1

# Debian-based (glibc), not Alpine (musl): libwolfssl_mldsa.so and the
# WolfSSL runtime lib bind-mounted in from the qkd_client project are built
# against glibc and won't load under musl's dynamic linker.
FROM python:3.10-slim-bookworm

ENV HOST=0.0.0.0
ENV PYTHONUNBUFFERED=1

COPY . /opt/next-door-key-simulator
WORKDIR /opt/next-door-key-simulator

RUN apt-get update && apt-get install -y --no-install-recommends bash curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir --upgrade pip setuptools
RUN pip install --no-cache-dir -r requirements.txt

RUN chmod +x start.sh
CMD ["./start.sh"]