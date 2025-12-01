# ===============================
# 1️⃣ Builder Stage
# ===============================
FROM python:3.11-slim AS builder

WORKDIR /app

# System deps ONLY for build
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

COPY . .

# ===============================
# 2️⃣ Runtime Stage (DISTROLESS)
# ===============================
FROM gcr.io/distroless/python3-debian12

WORKDIR /app

# Copy dependencies
COPY --from=builder /install /usr/local
COPY --from=builder /app /app

# ✅ distroless runs as non-root by default
EXPOSE 5000

CMD ["app.py"]
