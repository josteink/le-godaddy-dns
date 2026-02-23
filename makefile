
PYTHON="$(shell which python3)"
PYS = godaddy.py
PYCS = $(PYS:.py=.pyc)

all: $(PYCS) test

clean:
	rm -rf __pycache__ $(PYCS) .venv

.venv/ready:
	$(PYTHON) -m venv .venv
	touch $@

deps: .venv/ready
	.venv/bin/python -m pip install -r requirements.txt

test: deps
	+ .venv/bin/python -m unittest discover -v

%.pyc: %.py deps
	.venv/bin/python -m py_compile $<


# end
