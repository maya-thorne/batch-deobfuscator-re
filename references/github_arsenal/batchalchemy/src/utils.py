"""This module contains utility functions used by the other modules."""
import logging
import os
import tree_sitter as ts


def create_parser():
    """Utility function to build the parser for the batch language and return
    it as well as the tree-sitter Language object. This function is meant to be
    used before applying any transformations.

    :param: None
    :return parser: the tree-sitter parser for Batch
    :return batch_lang: the tree-sitter Language object for the Batch
        scripting language, used for syntax querying
    """

    root_dir = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
    parser_dir = os.path.join(root_dir, 'tree-sitter-batch')
    temp_dir = os.path.join(root_dir, 'temp')
    if not os.path.exists(temp_dir):
        os.mkdir(temp_dir)

    batch_so = os.path.join(temp_dir, 'batch-ts.so')
    ts.Language.build_library(batch_so, [parser_dir])

    batch_lang = ts.Language(batch_so, 'batch')
    parser = ts.Parser()
    parser.set_language(batch_lang)
    return parser, batch_lang


def remove_baum1810_overhead(src):
    """This function removes all lines in a batch file which start with the
    characters ``:%`` or the baum1810 obfuscation signature. Note: This
    function is not meant as a real deobfuscation tool because it changes the
    semantics of the batch. Thus, its purpose is simply for visualization,
    since the baum1810 obfuscator malformes the semantics of its input.

    :param src: The batch file given as input string.
    :return: The processed string.
    """
    list_ = []
    for line in src.splitlines():
        if ":%" not in line and "::obfuscated by https://github.com/baum1810" not in line:
            list_.append(line)

    return "\n".join(list_)


def replace_first_occurrence(original_str, old_substr, new_substr):
    """Replace the first occurrence of old_substring with new_substring in the
    original_string.

    :param original_str: string of the text which is to be edited
    :param old_substr: string which is to be searched and replaced
    :param new_substr: string by which old_substring is to be replaced
    :return: the processed input as string
    """
    first_occurrence_index = original_str.find(old_substr)

    if first_occurrence_index != -1:
        # Replace only the first occurrence
        result_string = (original_str[:first_occurrence_index] + new_substr +
                         original_str[first_occurrence_index + len(old_substr):])
        return result_string

    # If old_substring is not found, return the original string
    return original_str


def query_variable_substitutions(src, encoding="utf-8", stream="logging"):
    """Given the current state of a batch file, query the file for any variable
    substitutions which are detectable in the AST right now. Prints all found
    variables enclosed in ``%`` characters, either to stdout or on the logging
    DEBUG level, separated by newlines each.

    :param src: a string representation of the batch source file
    :param encoding: string encoding
    :param stream: a string that specifies the stream to which the list of found variables should be printed.
        Possible values are *"logging"* to log via root logger or *"stdout"* to print to standard output. Defaults to
        *"logging"*. Note that the logger's level must be set to ``logging.DEBUG`` to actually make the result visible.
    :return: None
    """

    parser, batch_lang = create_parser()

    tree = parser.parse(src.encode(encoding))

    # query all %variables% found in batch to log an overview
    query = batch_lang.query('''
        (variable_substitution) @var
    ''')

    # initialize string to append the output to
    out_string = "\n" + "=" * 80 + "\n"

    for capture in query.captures(tree.root_node):
        out_string += f"Found variable: {capture[0].text.decode(encoding)}\n"

    if stream == 'logging':
        logging.debug(out_string)
    elif stream == 'stdout':
        print(out_string)
    else:
        logging.warning(
            "Invalid value for stream parameter in query_variable_substitutions() specified. Hence,"
            "nothing will be printed.")
