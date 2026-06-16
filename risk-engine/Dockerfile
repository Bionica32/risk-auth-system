FROM python:3.10-slim
RUN apt-get update && apt-get install -y --no-install-recommends wget && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ./libs /app/libs

COPY main.py /app/main.py

# Чтобы Python видел /app/libs/pygost как пакет pygost
ENV PYTHONPATH=/app:/app/libs

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
