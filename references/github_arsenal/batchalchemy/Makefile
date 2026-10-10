.PHONY: clean help install
.DEFAULT_GOAL = help


########################################


all: setup beautify generate test ## Do all steps

clean: ## Clean the test case
	echo "Cleaning"

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'


########################################


setup: ## Setup CLI tools
	python -m pip install --upgrade pip
	python -m venv venv
	. venv/bin/activate             && \
	pip install -r requirements.txt && \
	pre-commit install
	npm install -g js-beautify
	cargo install tree-sitter-cli

beautify: ## Beautify the source files
	js-beautify -r ./tree-sitter-batch/grammar.js

test: ## Run the test suite
	cd tree-sitter-batch && \
	CXX=g++ tree-sitter test

generate: ## Generate the parser
	cd tree-sitter-batch && tree-sitter generate
