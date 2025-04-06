FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt ./
COPY entrypoint.sh ./

RUN chmod +x ./entrypoint.sh

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl build-essential \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv

ENV PATH="/root/.cargo/bin:${PATH}"
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- --profile minimal --default-toolchain none -y

RUN pip install --no-cache-dir -r requirements.txt

COPY ./files/ /app/

RUN mkdir -p /app/db /var/log

RUN groupadd -r apiuser && useradd -r -g apiuser apiuser

RUN chown -R apiuser:apiuser /app /var/log /venv

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "main.py"]
