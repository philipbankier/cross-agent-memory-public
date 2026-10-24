ARG TARGETARCH
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f AS base

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

FROM base AS python-amd64
ADD --checksum=sha256:178d3d83b6e8e99285a65d3fce9c16b87952cc5efdb4d1a0e3ff3be18ff0fc9c \
    https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz /tmp/python.tar.gz
RUN mkdir /opt/python \
    && tar -xzf /tmp/python.tar.gz -C /opt/python --strip-components=1 \
    && rm /tmp/python.tar.gz

FROM base AS python-arm64
ADD --checksum=sha256:9467a99bacc7d90b64b02de7fa9ecfc99b72905e64e74f7ff6b460ad95cfed5a \
    https://github.com/astral-sh/python-build-standalone/releases/download/20261013/cpython-3.12.15%2B20261013-aarch64-unknown-linux-gnu-install_only_stripped.tar.gz /tmp/python.tar.gz
RUN mkdir /opt/python \
    && tar -xzf /tmp/python.tar.gz -C /opt/python --strip-components=1 \
    && rm /tmp/python.tar.gz

FROM python-${TARGETARCH} AS python
ENV PATH=/opt/python/bin:${PATH} \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_DIR=/etc/ssl/certs
RUN ln -s /opt/python/bin/python3 /usr/local/bin/python \
    && python -I -B -c 'import sqlite3,ssl,sys; assert sys.version_info[:3] == (3,12,15); assert sqlite3.sqlite_version_info >= (3,51,3); assert ssl.create_default_context().cert_store_stats()["x509_ca"] > 0'

FROM python AS build

ENV PATH=/opt/cam/bin:${PATH} \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /build
ARG VCS_REF
RUN python -m venv /opt/cam
COPY pyproject.toml LICENSE README.md requirements.lock requirements-bootstrap.lock cam_build.py MANIFEST.in Containerfile .dockerignore compose.yaml ./
COPY script ./script
COPY browser/capture ./browser/capture
COPY docs/third-party ./docs/third-party
COPY ui/memory-app ./ui/memory-app
COPY src/cross_assistant_memory ./src/cross_assistant_memory
RUN python -m pip install --only-binary=:all: --require-hashes --requirement requirements-bootstrap.lock \
    && python -m pip install --only-binary=:all: --require-hashes --requirement requirements.lock \
    && python -m pip install --no-deps --no-build-isolation . \
    && python -m pip check \
    && python -m cross_assistant_memory.runtime_provenance "$VCS_REF"

FROM python AS runtime

ARG VCS_REF=unknown
LABEL org.opencontainers.image.title="Cross Assistant Memory" \
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.base.name="docker.io/library/debian:trixie-slim" \
      org.opencontainers.image.base.digest="sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f" \
      io.astral.python.release="20261013" \
      io.astral.python.version="3.12.15"

ENV CAM_HOME=/var/lib/cross-assistant-memory \
    CAM_PORT=8765 \
    HOME=/home/cam \
    PATH=/opt/cam/bin:${PATH} \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY --from=build /opt/cam /opt/cam
COPY --from=build /build/docs/third-party /usr/share/doc/cross-agent-memory/third-party
ADD --checksum=sha256:e43fb936c6655d7996dba480d7ebdea492d6040ec388eb8ed9d1000f72de8cab \
    https://raw.githubusercontent.com/astral-sh/python-build-standalone/9e40cba825ca0997a01cab9f60a0b15ffb976af2/python-licenses.rst /usr/share/doc/cross-agent-memory/python-runtime-licenses.rst
RUN chmod 0755 /usr/share/doc/cross-agent-memory \
    && chmod 0444 /usr/share/doc/cross-agent-memory/python-runtime-licenses.rst \
    && chmod 0755 /usr/share/doc/cross-agent-memory/third-party \
    && chmod 0444 /usr/share/doc/cross-agent-memory/third-party/* \
    && groupadd --gid 65532 cam \
    && useradd --uid 65532 --gid 65532 --home-dir /home/cam --create-home \
        --shell /usr/sbin/nologin cam \
    && install -d -o cam -g cam -m 0700 /var/lib/cross-assistant-memory

USER 65532:65532
WORKDIR /home/cam

HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=12 \
    CMD ["python", "-c", "import json,os,urllib.request; response=urllib.request.urlopen('http://127.0.0.1:'+os.environ['CAM_PORT']+'/health',timeout=2); assert response.status==200 and json.load(response)=={'status':'ok'}"]

ENTRYPOINT ["cross-memory"]
CMD ["serve", "--transport", "streamable-http", "--host", "127.0.0.1", "--port", "8765"]
