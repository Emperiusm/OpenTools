.PHONY: dev-api dev-ui test-api test-ui build-ui gen-types docker-up docker-down logs

# Development
dev-api:
	cd backend && uvicorn app.main:app --reload --port 8000

dev-ui:
	cd frontend && npm run dev

dev: ## Start both API and UI (run in separate terminals)
	@echo "Run 'make dev-api' in one terminal and 'make dev-ui' in another"

# Testing
test-api:
	cd backend && python -m pytest tests/ -v

test-ui:
	cd frontend && npm run build

test: test-api test-ui

# Build
build-ui:
	cd frontend && npm run build

# Docker
docker-up:
	docker compose up -d

docker-down:
	docker compose down

docker-rebuild:
	docker compose build --no-cache
	docker compose up -d

logs:
	docker compose logs -f api

logs-all:
	docker compose logs -f

# Database
db-migrate:
	cd backend && alembic upgrade head

db-revision:
	cd backend && alembic revision --autogenerate -m "$(msg)"

# Cleanup
clean:
	docker compose down -v
	rm -rf frontend/dist frontend/node_modules
