FROM python:3.12-slim

WORKDIR /workspace/backend

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/workspace:/workspace/backend

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY backend/requirements.txt /workspace/backend/requirements.txt
RUN pip install --no-cache-dir -r /workspace/backend/requirements.txt

COPY telemetry /workspace/telemetry
COPY backend /workspace/backend

EXPOSE 8000

CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

