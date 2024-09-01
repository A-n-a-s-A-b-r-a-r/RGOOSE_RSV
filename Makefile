SHELL := /bin/bash

BUILD_DIR := $(shell pwd)/build

#################################################

PYTHON_SCRIPTS := $(wildcard *.py)
EXE  := $(patsubst %.py, %, $(PYTHON_SCRIPTS))

#################################################

.PHONY: all clean check-all checks run

all: $(BUILD_DIR)

$(BUILD_DIR):
	@echo "Creating build dir..."
	@mkdir -p $@

run: $(BUILD_DIR)
	@echo "Running Python scripts..."
	@for script in $(PYTHON_SCRIPTS); do \
		echo "Running $$script"; \
		python $$script; \
	done

clean:
	rm -rf $(BUILD_DIR)

check-all: checks

checks:
	@echo "Output directory:"
	@echo $(BUILD_DIR)
	@echo "--------------------------------------------"
	@echo "PYTHON_SCRIPTS:"
	@echo $(PYTHON_SCRIPTS)
	@echo "--------------------------------------------"
	@echo "EXE:"
	@echo $(EXE)
	@echo "--------------------------------------------"
