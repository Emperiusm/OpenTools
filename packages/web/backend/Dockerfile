FROM python:3.14-slim

WORKDIR /app

# Install Docker CLI (for docker exec into tool containers)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl gnupg && \
    install -m 0755 -d /etc/apt/keyrings && \
    curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
    chmod a+r /etc/apt/keyrings/docker.asc && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" > /etc/apt/sources.list.d/docker.list && \
    apt-get update && apt-get install -y --no-install-recommends docker-ce-cli && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Install shared CLI library (for models, parsers, etc.)
COPY packages/cli/ /app/packages/cli/
RUN pip install --no-cache-dir /app/packages/cli/

# Copy plugin directory (recipes, config, tools)
COPY packages/plugin/ /app/packages/plugin/
ENV OPENTOOLS_PLUGIN_DIR=/app/packages/plugin

# Install web backend
COPY packages/web/backend/ /app/packages/web/backend/
RUN pip install --no-cache-dir /app/packages/web/backend/

WORKDIR /app/packages/web/backend

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
