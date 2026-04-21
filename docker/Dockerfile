FROM python:3.11-slim

# Nmap is required for the discovery stage.
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY sepulchrynscan/ ./sepulchrynscan/
COPY targets.allowlist .

ENTRYPOINT ["python", "-m", "sepulchrynscan.cli"]
