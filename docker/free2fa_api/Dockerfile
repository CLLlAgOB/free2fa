FROM python:slim

WORKDIR /app

COPY requirements.txt ./
COPY entrypoint.sh ./

RUN chmod +x ./entrypoint.sh

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv

RUN pip install --no-cache-dir -r requirements.txt

COPY ./files/ /app/

RUN mkdir -p /app/db /var/log

RUN groupadd -r apiuser && useradd -r -g apiuser apiuser

RUN chown -R apiuser:apiuser /app /var/log /venv

EXPOSE 5000

ENTRYPOINT ["./entrypoint.sh"]
CMD ["python", "main.py"]
