# ----------------------------------------
# STAGE 1: BUILDER
# ----------------------------------------
FROM python:3.12 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --prefix=/install --no-cache-dir -r requirements.txt
COPY . .

# ----------------------------------------
# STAGE 2: RUNTIME
# ----------------------------------------
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
 && addgroup --gid 10000 appuser \
 && adduser --uid 10000 --gid 10000 --disabled-password --gecos "" appuser \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /install /usr/local
COPY --from=builder /app /app
RUN chown -R 10000:10000 /app

USER appuser
EXPOSE 5000

CMD ["python", "app.py"]