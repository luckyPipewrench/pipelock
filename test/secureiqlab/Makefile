# SecureIQLab AI Security CyberRisk Validation — Test Harness
#
# Quick reference:
#   make init      Generate TLS CA (first time only)
#   make up        Start all containers
#   make down      Stop all containers
#   make smoke     Run smoke test
#   make fp-test   Run false positive test suite
#   make logs      Follow pipelock logs
#   make events    Query log collector events
#   make metrics   Show pipelock Prometheus metrics

.PHONY: init up down smoke fp-test logs events metrics summary clean rebuild

init:
	docker compose run --rm tls-init

up:
	@if [ ! -f configs/tls/ca.key ]; then \
		echo "TLS CA not found. Run 'make init' first."; \
		exit 1; \
	fi
	docker compose up -d

down:
	docker compose down

smoke:
	bash scripts/smoke-test.sh

fp-test:
	bash scripts/fp-test.sh

logs:
	docker compose logs -f pipelock

events:
	@curl -s http://localhost:9090/events | python3 -m json.tool 2>/dev/null || \
		curl -s http://localhost:9090/events

metrics:
	@curl -s http://localhost:9100/metrics | grep pipelock_

summary:
	@echo "=== Event Summary ==="
	@curl -s http://localhost:9090/events/summary | python3 -m json.tool 2>/dev/null || \
		curl -s http://localhost:9090/events/summary
	@echo
	@echo "=== Container Status ==="
	@docker compose ps

clean:
	docker compose down -v --rmi local
	rm -f configs/tls/ca.key configs/tls/ca.crt

rebuild:
	docker compose build --no-cache
