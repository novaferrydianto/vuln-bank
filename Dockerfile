FROM python:3.9-slim

# -----------------------------
# 1. System hardening essentials
# -----------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql-client \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------
# 2. Create non-root user
# -----------------------------
RUN addgroup --system appgroup \
    && adduser --system --ingroup appgroup appuser

WORKDIR /app

# -----------------------------
# 3. Install deps as root (one-time)
# -----------------------------
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# -----------------------------
# 4. Copy app files
# -----------------------------
COPY . .

# -----------------------------
# 5. Secure writable paths only
# -----------------------------
RUN mkdir -p /app/static/uploads \
    && chown -R appuser:appgroup /app/static/uploads \
    && chmod 750 /app/static/uploads

# -----------------------------
# 6. Drop privileges
# -----------------------------
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
