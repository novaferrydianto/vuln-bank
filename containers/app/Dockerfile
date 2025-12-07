# ============================================
# STAGE 1 — BUILDER
# ============================================
FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libpq-dev ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY containers/app/requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY app.py database.py auth.py ai_agent_deepseek.py ./
COPY templates ./templates
COPY static ./static

RUN python -m compileall /app


# ============================================
# STAGE 2 — DISTROLESS
# ============================================
FROM gcr.io/distroless/python3-debian12

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/usr/local/lib/python3.11/site-packages

WORKDIR /app

COPY --from=builder /install /usr/local
COPY --from=builder /app /app

USER nonroot:nonroot

EXPOSE 5000

# ✅ DO NOT repeat python here
CMD ["-u", "app.py"]
