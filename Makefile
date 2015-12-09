# Andy Sayler
# 2015

ECHO = @echo

GIT = git

PYTHON = python3
PIP = pip3

REQUIRMENTS = requirments.txt

PYTUTAMEN_DIR = "./submodules/tutamen-pytutamen"

UNITTEST_PATTERN = '*_test.py'

.PHONY: all git reqs test clean

all:
	$(ECHO) "This is a python project; nothing to build!"

git:
	$(GIT) submodule init
	$(GIT) submodule update

reqs:
	$(PIP) install -r $(REQUIRMENTS) -U
	$(MAKE) -C $(PYTUTAMEN_DIR) reqs3

test:
	$(PYTHON) -m unittest discover -v -p $(UNITTEST_PATTERN)

clean:
	$(RM) *.pyc
	$(RM) *~
	$(MAKE) -C $(PYTUTAMEN_DIR) clean
