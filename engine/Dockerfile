# Runs the background service: simulator, detection, scenarios, connector, forwarding and retention.
# Works on Render, Railway and Fly.io as a worker with no public port.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --create-home --uid 10001 htm
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY config ./config
COPY simulator ./simulator
COPY detection ./detection
COPY connectors ./connectors
COPY receiver ./receiver
COPY forwarding.py worker.py evaluate.py ./
COPY docker-entry.sh /usr/local/bin/env-entry
RUN mkdir runs && chown htm runs
USER htm

# DATABASE_URL, HTM_API_URL, HTM_COLLECTOR_SECRET and SIEM_WEBHOOK_KEY come from the host's environment,
# or from a file named by HTM_ENV_FILE, as in the one command demo.
# To run the webhook connector from this image instead, set the start command to: python -m connectors.webhook_connector
# The hospital installation also runs the log receiver from this image, with: python -m receiver
ENTRYPOINT ["/usr/local/bin/env-entry"]
CMD ["python", "-m", "worker"]
