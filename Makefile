# Reproducible runners (spec section 30). Windows users can call the Python
# runners directly, e.g. `python runners/run_e2.py`.

.PHONY: help setup db-up db-down run_e1 run_e2 run_e3 run_all test clean

help:
	@echo "setup    - install python deps"
	@echo "db-up    - start lab PostgreSQL (E3)"
	@echo "db-down  - stop lab PostgreSQL"
	@echo "run_e2   - E2 Replay experiment"
	@echo "run_e3   - E3 SQL Injection experiment (needs db-up)"
	@echo "run_e1   - E1 ARP/MITM experiment (needs Docker)"
	@echo "run_all  - run E2, E3, E1"
	@echo "test     - pytest acceptance + unit + security suites"

setup:
	python -m pip install -r requirements.txt

db-up:
	docker compose up -d postgres

db-down:
	docker compose down

run_e2:
	python runners/run_e2.py

run_e3:
	python runners/run_e3.py

run_e1:
	python runners/run_e1.py

run_all:
	python runners/run_all.py

test:
	python -m pytest -q

clean:
	docker compose down || true
	docker compose -f labs/e1_arp/docker/docker-compose.e1.yml down || true
