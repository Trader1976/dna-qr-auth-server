FROM python:3.12-slim

WORKDIR /app

# Toolchain + libc headers (stdint.h lives here)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
 && rm -rf /var/lib/apt/lists/*

COPY ./app /app/app

#COPY ./requirements.txt /app/requirements.txt
#RUN pip install --no-cache-dir -r requirements.txt

COPY ./requirements-server.txt /app/requirements-server.txt
RUN pip install --no-cache-dir -r requirements-server.txt


# Build native verifier from PQClean (ML-DSA-87)
RUN cd /app/app/native && gcc -O2 -fPIC -shared \
    -I/app/app/native/PQClean/crypto_sign/ml-dsa-87/clean \
    -I/app/app/native/PQClean/common \
    /app/app/native/dilithium_verify.c \
    /app/app/native/PQClean/crypto_sign/ml-dsa-87/clean/*.c \
    /app/app/native/PQClean/common/*.c \
    -o /app/app/native/libdna_pq_verify.so

EXPOSE 9000
#CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "9000"]
