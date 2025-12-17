# ============================================
# STAGE 1 — BUILDER
# ============================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# [UBAH DISINI] Ambil requirements dari dalam folder containers/app
COPY containers/app/requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ============================================
# STAGE 2 — PRODUCTION
# ============================================
FROM gcr.io/distroless/python3-debian12

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

WORKDIR /app

COPY --from=builder /install /usr/local

# Copy source code (Asumsi app.py ada di root repository)
COPY app.py database.py auth.py ai_agent_deepseek.py ./
COPY templates ./templates
COPY static ./static

USER nonroot:nonroot

EXPOSE 5000

CMD ["-u", "app.py"]