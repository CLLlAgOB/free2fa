FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/venv \
    PATH="/venv/bin:/root/.cargo/bin:${PATH}"

WORKDIR /app

COPY requirements.txt ./requirements.txt
COPY --chmod=0755 entrypoint.sh ./entrypoint.sh

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        gosu \
    ; \
    rm -rf /var/lib/apt/lists/*; \
    python -m venv "${VIRTUAL_ENV}"; \
    pip install --no-cache-dir --upgrade \
        pip \
        setuptools \
        wheel \
    ; \
    pip install --no-cache-dir -r /app/requirements.txt; \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- --profile minimal --default-toolchain none -y

COPY ./files/ /app/

RUN set -eux; \
    mkdir -p /app/db /app/certs /var/log /opt/db; \
    groupadd -r apiuser || true; \
    useradd  -r -g apiuser apiuser || true; \
    chown -R apiuser:apiuser /app /var/log /venv /opt/db

EXPOSE 5000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["python", "main.py"]
