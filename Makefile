.PHONY: report demo gate test data

report:   ## before/after protection report
	python -m guardrails.run

demo:     ## concrete walkthrough of the real bug it stops
	python -m guardrails.demo

gate:     ## CI mode: non-zero exit if protection regressed
	python -m guardrails.run --gate

test:     ## the guarantees, as tests
	python -m pytest -q

data:     ## regenerate the deterministic battery
	python scripts/make_data.py
