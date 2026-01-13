FROM python:3.12-slim

WORKDIR /app

# --- system deps for native build ---
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc make \
 && rm -rf /var/lib/apt/lists/*

# --- app code ---
COPY ./app /app/app
COPY ./requirements.txt /app/requirements.txt

# --- python deps ---
RUN pip install --no-cache-dir -r requirements.txt

# --- build native ML-DSA-87 verifier (PQClean) ---
RUN set -eux; \
    test -f /app/app/native/PQClean/crypto_sign/ml-dsa-87/clean/api.h; \
    cd /app/app/native; \
    gcc -O2 -fPIC -shared \
      -I/app/app/native/PQClean/crypto_sign/ml-dsa-87/clean \
      -I/app/app/native/PQClean/common \
      dilithium_verify.c \
      /app/app/native/PQClean/crypto_sign/ml-dsa-87/clean/*.c \
      /app/app/native/PQClean/common/*.c \
      -o libdna_pq_verify.so; \
    ls -la /app/app/native/libdna_pq_verify.so

EXPOSE 9000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
