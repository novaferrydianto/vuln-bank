# -----------------------------
# STAGE 1 — BUILDER (install deps safely)
# -----------------------------
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt


# -----------------------------
# STAGE 2 — RUNTIME (minimal)
# -----------------------------
FROM python:3.11-slim

# Security: Remove pip, build tools, cache, compilers
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python*/distutils \
    && rm -rf /usr/local/bin/pip

# Add non-root user
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser

WORKDIR /app

# Copy installed deps only
COPY --from=builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy app source
COPY . .

# Allow only specific writable dirs
RUN mkdir -p /app/static/uploads \
    && chown -R appuser:appgroup /app/static/uploads \
    && chmod 750 /app/static/uploads

USER appuser

EXPOSE 5000

CMD ["python", "-u", "app.py"]
