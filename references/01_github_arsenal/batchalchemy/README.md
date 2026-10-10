# Welcome to the BatchAlchemy Research Project!
BatchAlchemy is a cyber security related research project designed to address the need for a robust deobfuscation framework for the Windows Batch scripting language.
Traditional deobfuscation tools operate on the principle of identifying a known obfuscation method and crafting a rigid deobfuscator for it.
With BatchAlchemy, we aim to provide a novel solution by offering malware analysts an easy-to-maintain and easy-to-extend tool capable of crafting tailored responses to both known and upcoming obfuscation samples.
The framework is based on a Batch parser (based on the Tree-sitter parser generator tool), enabling to work with the Abstract Syntax Tree (AST) of obfuscated files.

Concerning future research, the most valuable insights have been gathered during our in-depth analysis of the Batch syntax. We collected the most interesting findings of nuances of how Batch internally gets parsed by the Windows Command Prompt (cmd.exe) in a summary located [***HERE***](https://batchalchemy.github.io/). Because of the lack of official Batch syntax documentation, we are certain that our findings are valuable for every cyber security researcher who tries to enhance their understanding of all the weird and nitty details of Batch.

## Our research
- The write-up of our most interesting findings on the nuances of the Batch scripting language can be found [***HERE***](https://batchalchemy.github.io/).
- The scientific report can be found [***HERE***](https://github.com/BatchAlchemy/batchalchemy/blob/main/Unveiling_Batch_Script_Obfuscation_report.pdf).
- The slides of our presentation can be found [***HERE***](https://github.com/BatchAlchemy/batchalchemy/blob/main/Unveiling_Batch_Script_Obfuscation_slides.pdf).

## Repo structure

Giving some directions to the most important directories of this project:
- The front end is located at [`batchalchemy/tree-sitter-batch`](https://github.com/BatchAlchemy/batchalchemy/tree/main/tree-sitter-batch)
  - For the main part of the frontend (aka the **tree-sitter grammar** for the parser), see [`batchalchemy/tree-sitter-batch/grammar.js`](https://github.com/BatchAlchemy/batchalchemy/blob/main/tree-sitter-batch/grammar.js)
  - For the **corpus** (test-driven-development), see [`batchalchemy/tree-sitter-batch/corpus`](https://github.com/BatchAlchemy/batchalchemy/tree/main/tree-sitter-batch/corpus)
- The backend (aka the **extensible toolkit for deobfuscation**) is located at [`batchalchemy/src`](https://github.com/BatchAlchemy/batchalchemy/tree/main/src)
  - For **sphinx documentation** of the backend, open up [`batchalchemy/docs/_build/html/index.html`](https://github.com/BatchAlchemy/batchalchemy/blob/main/docs/_build/html/index.html) in your favorite browser

---

## Requirements (in general)

- `python3`
- `python3-pip` for `pip install tree-sitter`
- `node.js`
- `cargo`, `npm` or download the `tree-sitter binary` from its GitHub and put it into `PATH`
- C compiler

## Requirements (for setup via Makefile on Linux)

- `python3-pip`
- `python3-venv`
- `node`
- `cargo`
- C compiler

## Setup via Makefile on Linux

Running `make setup` will create a virtual python environment, install the dependencies and set up sane defaults for code formatting and linting.

Activate the virtual environment by running `source ./venv/bin/activate`
