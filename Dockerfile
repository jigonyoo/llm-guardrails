# Pure standard library — no pip install, no network, no API key.
FROM python:3.11-slim
WORKDIR /app
COPY . /app
# Default: print the before/after report. Override with e.g.
#   docker compose run guardrails python -m guardrails.demo
CMD ["python", "-m", "guardrails.run"]
