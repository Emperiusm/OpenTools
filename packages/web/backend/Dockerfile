FROM python:3.14-slim

WORKDIR /app

# Install shared CLI library (for models, parsers, etc.)
COPY packages/cli/ /app/packages/cli/
RUN pip install --no-cache-dir /app/packages/cli/

# Install web backend
COPY packages/web/backend/ /app/packages/web/backend/
RUN pip install --no-cache-dir /app/packages/web/backend/

WORKDIR /app/packages/web/backend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
