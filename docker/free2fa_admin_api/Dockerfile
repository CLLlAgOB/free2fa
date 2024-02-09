FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY adminapi.py ./adminapi.py
COPY entrypoint.sh ./entrypoint.sh

RUN chmod +x ./entrypoint.sh

RUN groupadd -r apiuser && useradd --create-home -r -g apiuser apiuser

RUN chown -R apiuser:apiuser /app

EXPOSE 8000

ENTRYPOINT ["./entrypoint.sh"]