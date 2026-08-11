.PHONY: test test-staged test-direct config down clean

# Full test: staged (recommended) upgrade path, then the naive direct-jump path
test:
	python3 run_test.py --scenario both

test-staged:
	python3 run_test.py --scenario staged

test-direct:
	python3 run_test.py --scenario direct

# Validate docker-compose.yml without needing registry access
config:
	docker compose config

down:
	docker compose down -v

clean: down
	rm -rf results/report.md results/report.json
