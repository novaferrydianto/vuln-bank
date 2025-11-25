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

RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    && adduser --system --no-create-home appuser \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /install /usr/local

COPY --from=builder /app /app

RUN chown -R appuser /app
RUN mkdir -p static/uploads templates
RUN chmod 775 static/uploads

EXPOSE 5000

USER appuser

CMD ["python", "app.py"]