# Fincrypt — one command surface for humans and CI.
# Targets: dev, web-dev, test, test-web, lint, lint-web, build, build-web,
#          migrate, compose-up, compose-down, ci

GO ?= go
WEB_DIR := web
MIGRATIONS_DIR := db/migrations

.PHONY: dev web-dev test test-web lint lint-web build build-web migrate compose-up compose-down ci

## Full dev loop: Postgres up + migration + Go server (web: `make web-dev` in a second shell)
dev:
	docker compose up -d postgres
	$(GO) run ./cmd/server

## Web dev server (expects `make dev` running for /api proxy)
web-dev:
	cd $(WEB_DIR) && npm run dev

## Go tests (unit; DB tests need `docker compose up -d postgres` and DATABASE_URL)
test:
	$(GO) test ./...

test-web:
	cd $(WEB_DIR) && npm run test -- --run

lint:
	golangci-lint run

lint-web:
	cd $(WEB_DIR) && npm run lint

build:
	$(GO) build -o bin/server ./cmd/server

build-web:
	cd $(WEB_DIR) && npm run build

## Apply pending migrations (uses DATABASE_URL from env / .env)
migrate:
	$(GO) run ./cmd/server --migrate-only

compose-up:
	docker compose up -d --build

compose-down:
	docker compose down

## Everything CI runs — use before pushing
ci: lint test test-web lint-web build build-web
	@echo "all local gates green"