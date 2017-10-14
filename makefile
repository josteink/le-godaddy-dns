
PYTHON="$(shell which python3)"
PYS = godaddy.py
PYCS = $(PYS:.py=.pyc)

all: $(PYCS) test

test:
	+ $(PYTHON) -m unittest discover -v

%.pyc: %.py
	$(PYTHON) -m py_compile $<

clean:
	rm -rf __pycache__ $(PYCS)

# end
