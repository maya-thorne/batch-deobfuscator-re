"""This file is used to test the tree-sitter-batch parser."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# pylint: disable=logging-not-lazy
# pylint: disable=missing-function-docstring
# pylint: disable=invalid-character-esc
# pylint: disable=anomalous-backslash-in-string
# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import
# flake8: noqa

from deobfuscator import *
from formatting import to_lower_case
import tests
import utils
import logging
import os


if __name__ == '__main__':
    """
        This is the place to decide what tools are to be used to beat the obfuscation and how the input looks like.

        List of possible tools currently include:

        - batch file manipulations:
            - command_name_cleaner(src, encoding): remove escaping carets from command_names
            - constant_folding(src, encoding): condense arithmetic expressions to constants
            - to_lower_case(src, encoding, force, keywords, rules): transform to lower case, choosing between different
                modes which differ in what parts of the input get transformed
            - variable_substitution(src, encoding, expand_local, expand_env, placeholder): removes unset and probably
                never to be used variables and gives options to either expand locally set variables as well as variables
                which are currently set in the environment or leave them untouched
        - printing / debugging tools:
            - format_s_exp(input_str, indent_size): print the tree structure for a one-liner S-expression
            - query_separators(src, encoding, stream): output all queried separators to either the root logger or stdout
            - query_variable_assignments(src, encoding, stream): output all queried variable assignments to either
                the root logger or stdout
            - query_variable_substitutions(src, encoding, stream): output all queried variable substitutions to either
                the root logger or stdout
        - helper functions:
            - create_parser(): given the batch language tree-sitter files, create a parser to be able to yield ASTs
            - replace_first_occurrence(original_str, old_substr, new_substr): replace the first occurrence of
                a substring in the input string with another value.
        - test functions:
            - test_abobus(): pipeline for using deobfuscating means, given an exemplary abobus-obfuscated batch file
            - test_baum1810(): pipeline for using deobfuscating means, given an exemplary baum1810-obfuscated batch file
            - test_baum1810_obfuscated_malware_samples(): testing if baum1810 obfuscated malware samples against the
                baum1810 pipeline to evaluate its success
        - other functions:
            - remove_baum1810_overhead(): remove the additional lines of code that the baum1810 obfuscator prepends
            - modify_nodes(): meant to experiment with tree-sitter's node traversing; this function can be ignored
            - remove_separators(src, encoding, placeholder): remove obfuscating usage of whitespace and non-whitespace
                separators; warning: currently not working! raises NotImplementedError
    """

    # set debug level for stderr messages, e.g. logging.DEBUG, logging.WARNING, ...
    logging.basicConfig(level=logging.DEBUG)

    # test_baum1810()
    tests.test_abobus()
