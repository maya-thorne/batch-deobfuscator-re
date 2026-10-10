.. Batchger documentation master file, created by
   sphinx-quickstart on Sat Jan 13 22:15:04 2024.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to Batchger's documentation!
====================================

This project revolves around a framework developed for the Batch scripting language, aimed at deobfuscating obfuscated Batch scripts. The emphasis lies on ensuring that the deobfuscation methods operate based on Abstract Syntax Trees (ASTs) of Batch scripts.
The framework comprises two main components: the parser (*frontend*) and the toolbox of deobfuscation techniques (*backend*).

The frontend
""""""""""""
The parser is built on Tree-sitter (link to homepage: https://tree-sitter.github.io/tree-sitter/), a parser generator tool designed for the Batch syntax. It is written in JavaScript and leverages the Node.js execution environment provided by Tree-sitter. The parser primarily handles the parsing of Batch scripts and almost all syntax-related aspects. Parsing a Batch file with the parser yields an AST according to the Batch grammar developed by us.

Typically, a Tree-sitter grammar consists of rules, which mostly employ regular expressions at their lowest level. The parsing process starts with the main rule (``source_file``), which gradually divides the entire Batch file into so-called *statements*, which are further broken down into finer-grained components until reaching the lowest level.

*For example*, given the Batch file containing the following line
``ec%var_not_set%ho & rem comment``
the resulting AST would be:

.. code::

    (source_file
        (command
            (command_name
                (variable)))
        (comment))

This AST represents the entire Batch file (``source_file``), with two statements (separated by the unconditional execution symbol ``&``). The first statement is a command (``command``), consisting of a command name (``command_name``) containing a substitutable variable (``variable``).  The second statement is a simple comment (``comment``). Note that if the line gets executed by the Windows Command Prompt (*cmd.exe*), first the variable inside will be substituted; in case its value is *null*/empty, the line becomes ``echo & rem comment``, which prints the current echo setting (*ON* or *OFF*).

Statements are the basic building blocks identified for the Batch scripting language, representing the syntactic elements that a Batch file can consist of. These include, among others, for loops, conditional execution, labels, variable assignments, and more. A complete list is available in the ``grammar.js`` file located at ``batchger/tree-sitter-batch/grammar.js``.

Because the frontend is not yet submitted to the official tree-sitter contribution project, it has to be manually built to work. A detailed guide can be found on the tree-sitter homepage under "Creating parsers" (https://tree-sitter.github.io/tree-sitter/creating-parsers). To sum it up, you basically have to navigate in this project's *tree-sitter-batch*-folder and execute ``tree-sitter generate`` (make sure to fulfill the prerequisites for tree-sitter, see https://tree-sitter.github.io/tree-sitter/creating-parsers#dependencies and https://tree-sitter.github.io/tree-sitter/creating-parsers#installation). After that, you can execute the test corpus via ``tree-sitter test`` or use the backend functionality located in the *batchger42/src* folder.

The backend
"""""""""""
The second part of the framework is the backend, which comprises the collection of extensible functionalities for defeating obfuscators. For reasons of maintainability, extensibility, and usability, it is written in pure Python. The goal of the backend is not to have all deobfuscation techniques implemented upon release, but to provide analysts with a tool that allows them to build on existing knowledge or expand the existing Swiss army knife with new functionalities, without rigidly focusing on a specific obfuscator.

The scenario is as follows: When encountering a new obfuscator, malware researchers can use the framework to generate the AST of the obfuscated Batch file using the Tree-sitter API, and then:

* utilize existing functions of the framework,
* write new ones (i.e., extend the optimizer), or
* link existing functions or new functions together to defeat any obfuscator.

The backend is responsible for this functionality, and its features and usage are explained in this documentation. Below are the links to the documentation of the python files involved in the backend, comprising of five different categories, which can be seen under **Contents**.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   deobfuscator
   experimental
   formatting
   optimizer
   tests
   utils

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
