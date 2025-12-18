FROM python:3.13-slim

WORKDIR /app

# Setup dependencies
COPY requirements.txt .
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends gosu; \
    rm -rf /var/lib/apt/lists/*; \
    pip install --no-cache-dir -r requirements.txt

# Copy the code and entry point
COPY adminapi.py ./adminapi.py
COPY --chmod=0755 entrypoint.sh ./entrypoint.sh

# Creating a user
RUN groupadd -r apiuser && useradd -r -g apiuser apiuser

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
