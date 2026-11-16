.PHONY: install run seed test clean docker-up docker-down

install:
	python -m pip install -r requirements.txt

run:
	uvicorn app.main:app --reload

seed:
	python scripts/seed_demo.py

test:
	pytest -q

clean:
	rm -f vulnprior.db test_vulnprior.db

docker-up:
	docker compose up --build

docker-down:
	docker compose down
