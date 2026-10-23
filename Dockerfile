FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

WORKDIR /app

COPY pyproject.toml README.md LICENSE /app/
COPY scamshield /app/scamshield

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir .

EXPOSE 8000

CMD ["sh", "-c", "uvicorn scamshield.api:app --host 0.0.0.0 --port ${PORT}"]
