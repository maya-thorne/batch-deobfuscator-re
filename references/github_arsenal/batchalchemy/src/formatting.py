"""This module contains functions to format batch files."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# pylint: disable=logging-not-lazy
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# flake8: noqa

import logging
import re
import utils


# pylint: disable=unreachable
def remove_separators(src, encoding="utf-8", placeholder=b'#'):
    """Removes all separators which are to be identified by the separator-node
    of the AST. Processes the given input in just one run and returns the
    processed string.

    :param src: a string representing the current state of the batch file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is *"utf-8"*
    :param placeholder: an ascii bytes literal of length 1 that is used to temporarily mark separator positions;
        after all the marking is done, every grouped occurrence of it gets replaced by a single whitespace
        character. Caution! To guarantee correctness, this parameter should not occur in src anywhere. Defaults to
        *b'#'*
    :return: the processed string
    """
    raise NotImplementedError(
        "This function can't be implemented anymore since separators have been removed! Check commit d320fbc"
    )

    out_string = src

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(out_string.encode(encoding))

    # log an overview of all variables at the start; debug purposes only
    query_separators(out_string, stream='logging')

    logging.debug("\n" + "=" * 80 + "\n")

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    # query all separators found in batch
    query = batch_lang.query('''
                (separators) @sep
            ''')

    # grab occurrences of separators which are meant to be marked with the placeholder
    for capture in query.captures(tree.root_node):
        separators_as_str = capture[0].text.decode(encoding)
        logging.debug("Now marking with placeholder $.separators:" + separators_as_str)

        # keep in mind that this all starts at (0,0), unlike e.g. the Pycharm IDE, which starts at (1,1)
        startb = capture[0].start_byte
        endb = capture[0].end_byte

        # simply cut out the variable since it has no value
        # since we only get positional information of the byte representation, operate on bytes here
        out_bytes = out_string.encode(encoding)
        # for each single separator character replace it by the placeholder character
        out_string = (out_bytes[:startb] + placeholder * abs(endb - startb) +
                      out_bytes[endb:]).decode(encoding)

        # reparsing using the old tree, just for efficiency
        tree = parser.parse(out_string.encode(encoding))

        logging.debug("\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    # cleaning step: replace placeholder with a single whitespace each
    pattern = re.escape(f"{placeholder.decode(encoding)}") + r"+"
    out_string = re.sub(pattern, ' ', out_string)

    # cleaning step: remove left leading whitespaces for a clean indentation of the batch script
    out_string = "\n".join(line.lstrip() for line in out_string.splitlines())

    return out_string


def format_sexp(input_str, indent_size=4):
    """Given a string as input which is a valid S-expression which again is
    formatted in one line only, this function processes this string and returns
    the semantically same S-expression but with added newlines and indentations
    to make it a visually appealing tree structure. This helps in visualizing
    S-expressions returned by tree-sitter's ``tree-sitter.Node.sexp()`` method.

    :param input_str: a valid S-expression one-liner
    :param indent_size: an integer stating the size of individual
        indentations, defaults to *4*
    :return: the formatted input_string with indentations and newline
        suited for output
    """
    output_string = ""
    indentation = 0

    for char in input_str:
        if char.isspace():
            output_string += '\n' + ' ' * indentation
        elif char == '\n':
            # reset indentation if multiple lines are given
            indentation = 0
        elif char == '(':
            output_string += char
            indentation += indent_size
        elif char == ')':
            output_string += char
            indentation -= indent_size
        else:
            output_string += char

    return output_string


def to_lower_case(
    src,
    encoding="utf-8",
    force=False,
    keywords=('for', 'set', 'if', 'errorlevel', 'cmdextversion', 'defined', 'exist', 'else'),
    rules=(
        '(command (command_name) @cmdname)',
        # '(command) @cmd',
        # '(if_statement) @if',
        # '(assignment) @ass',
        # '(for_statement) @for',
        '(comment) @comment',
        '(label_definition) @label')):
    """Given an input batch file, this function transforms its content to lower
    case. For that, three different modes are available. The first is to simply
    force lower case across the entire input. In case of enabling the first
    mode (force), the other two are being skipped automatically. The second and
    the third can be used separately or in tandem. One of which is to state a
    number of rules (formatted as tree-sitter S-expressions). This processes
    the batch file in a way that every matched character within any match of
    this set of rules gets lower cased. The last mode is meant to just lower
    case a set of keywords which can be processed by the batch parser. This
    aims at preventing the loss of information concerning semantically relevant
    case-sensitiveness. Caution! In its current state of implementation, not
    every keyword can be lower cased fully correctly. Thus, the function's
    default values are set to yield stable solutions only.

    TODOs:

    - TODO currently assumes a certain degree of previous deobfuscation (no escaping carets, detectable rules, thus
      after resolved variable expansions)
    - TODO hence, either implement carets in the RegExes of re.sub() or implement the deobfuscating function itself
      and beware the changes in the ranges! aka update tree!

    :param src: a string representation of the batch source file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is *"utf-8"*
    :param force: boolean specifying whether to force the entire batch file to lower case or not. Defaults to
        *False*.
    :param keywords: iterable of strings representing keywords which can be processed by the batch parser. Valid
        strings are *'for', 'in', 'do', 'set', 'if', 'not', 'else', 'errorlevel', 'cmdextversion', 'defined',
        'exist', 'equ', 'neq', 'lss', 'lew', 'gtr'* and *'geq'*. For each listed keyword, the function lower cases
        every match of that keyword in src. This parameter is only taken into account if the force parameter is set
        to False. Defaults to *('for', 'set', 'if', 'errorlevel', 'cmdextversion', 'defined', 'exist', 'else')*,
        because these are the currently stable ones for processing correctly to lower case. Use remaining keywords
        with caution.
    :param rules: iterable of strings representing rules which can be processed by the batch parser. Each rule must
        have the format of a typical tree-sitter S-expression, including an identifier (which consists out of an
        ``@`` character and an alphabetical string immediately thereafter). The S-expression is used to check the
        AST of the input batch file for any occurrence of that parsing structure, whereas the identifier marks the
        position / the part of the S-expression which should be lower cased. To mark a specific part of the
        S-expression, the identifier must be placed after the corresponding closing parenthesis, including a
        whitespace. The actual name of the identifier is not relevant, as it is only used as a marker. Note that
        variables stay case sensitive. This parameter is only taken into account if the force parameter is set to
        False.

        Defaults to the following iterable, which includes three rules, that is to process command names, comments
        and label definitions:

        *('(command (command_name) @cmdname)',*

        *'(comment) @comment',*

        *'(label_definition) @label')*
    :return: the processed string
    """

    out_string = src

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(out_string.encode(encoding))

    logging.debug("\n" + "=" * 80 + "\n")

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    # if desired, use the following debugging code line to show the AST after each step
    logging.debug(format_sexp(tree.root_node.sexp()))

    #################
    # MODE 1: FORCE #
    #################
    # the force flag is dominant; lower case everything and just return
    if force:
        out_string = out_string.lower()
        return out_string

    ####################
    # MODE 2: KEYWORDS #
    ####################
    # categorize keywords into lists: each list makes use of another query for the processing
    for_keywords = ['for', 'in', 'do']
    set_keywords = ['set']
    if_keywords = ['if', 'not']
    else_keywords = ['else']
    unexp_keywords = ['errorlevel', 'cmdextversion']
    uiexp_keywords = ['defined', 'exist']
    comp_keywords = ['equ', 'neq', 'lss', 'lew', 'gtr', 'geq']

    # a list containing all of the lists above to be able to iterate over all of the lists for the for loop below
    keywords_lists = [
        for_keywords, set_keywords, if_keywords, else_keywords, unexp_keywords, uiexp_keywords,
        comp_keywords
    ]

    # for each list of keywords
    for keywords_list in keywords_lists:
        # check if there is a cut between the currently iterated list and the list of keywords which should be
        #  considered for the lower case processing step; if not, just skip all the keywords in that list
        if bool(set(keywords) & set(keywords_list)):
            # make the decision what list we are currently taking a look at (and prepare the query for the next steps)
            if keywords_list == for_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: for_keywords")
                query = batch_lang.query("""(for_statement) @for""")
            elif keywords_list == set_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: set_keywords")
                query = batch_lang.query("""(assignment) @set""")
            elif keywords_list == if_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: if_keywords")
                query = batch_lang.query("""(if_statement) @if""")
            elif keywords_list == else_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: else_keywords")
                query = batch_lang.query("""(else_clause) @else""")
            elif keywords_list == unexp_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: unexp_keywords")
                query = batch_lang.query("""(unary_numerical_expression) @unexp""")
            elif keywords_list == uiexp_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: uiexp_keywords")
                query = batch_lang.query("""(unary_identifier_expression) @uiexp""")
            elif keywords_list == comp_keywords:
                logging.debug(
                    "\n" + "=" * 80 +
                    "\nNow starting the lower case transforming with keyword-list: comp_keywords")
                query = batch_lang.query("""(comparison_expression) @comp""")
            else:
                continue

            # only take a look at the processing loop if there are any matches for the current query / keyword_list
            if query.captures(tree.root_node):
                # iterate over all matches found in the batch for the current keyword_list
                for capture in query.captures(tree.root_node):
                    capture_as_str = capture[0].text.decode(encoding)
                    startb = capture[0].start_byte
                    endb = capture[0].end_byte
                    # iterate over all keywords that are in the current list AND that should be lower cased (see param)
                    for keyword in (set(keywords) & set(keywords_list)):
                        # substitute the first occurrence of the keyword with its lower case
                        capture_as_str = re.sub(keyword, keyword, capture_as_str, 1, re.IGNORECASE)
                        out_bytes = out_string.encode(encoding)
                        # update output, taking the old output but having the processed keywords replaced
                        out_string = (out_bytes[:startb] + capture_as_str.encode(encoding) +
                                      out_bytes[endb:]).decode(encoding)

                # reparsing using the old tree, just for efficiency
                tree = parser.parse(out_string.encode(encoding), tree)
                logging.debug("--->After lower case transforming with the keyword-list:\n" +
                              tree.text.decode(encoding) + "\n" + "=" * 80)

    #################
    # MODE 3: RULES #
    #################
    for rule in rules:
        logging.debug("Now starting the lower case transforming with rule:" + rule)

        # query variables which are set in this batch file to make list of variables which should not be gotten rid of
        query = batch_lang.query(rule)

        # finish when nothing was captured anymore, meaning that no %variables% are left in the batch file
        if not query.captures(tree.root_node):
            continue

        for capture in query.captures(tree.root_node):
            query_as_str = capture[0].text.decode(encoding)
            logging.debug("--->Now transforming to lower case:" + query_as_str)

            # keep in mind that this all starts at (0,0), unlike e.g. the Pycharm IDE, which starts at (1,1)
            startb = capture[0].start_byte
            endb = capture[0].end_byte

            lower_case_string = ""

            # since variable names are case sensitive, do not lower case them, even if they are part of a
            if '%' in query_as_str:
                inside_variable = False
                for char in query_as_str:
                    if char == '%':
                        inside_variable = not inside_variable
                    lower_case_string += char.lower() if not inside_variable else char
            else:
                # if there is no variable in it, simply lower case the entire rule, as intended
                lower_case_string = query_as_str.lower()

            lower_case_bytes = lower_case_string.encode(encoding)

            out_bytes = out_string.encode(encoding)
            # update output, taking the old output but having the part which is matched by the rule replaced
            out_string = (out_bytes[:startb] + lower_case_bytes + out_bytes[endb:]).decode(encoding)

            # reparsing using the old tree, just for efficiency
            tree = parser.parse(out_string.encode(encoding), tree)

            logging.debug("\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    logging.debug("\n" + "=" * 80 + "\nEND:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    return out_string


def query_separators(src, encoding="utf-8", stream="logging"):
    """Given the current state of a batch file, query the file for any
    separators which are detectable in the AST right now. Prints all found
    separators either to stdout or on the logging DEBUG level, separated by
    newlines each.

    :param src: a string representation of the batch source file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is "utf-8"
    :param stream: a string that specifies the stream to which the list of found variables should be printed.
        Possible values are *"logging"* to log via root logger or *"stdout"* to print to standard output. Defaults
        to *"logging"*. Note that the logger's level must be set to ``logging.DEBUG`` to actually make the result
        visible.
    :return: None
    """

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(src.encode(encoding))

    # query all separators found in batch to log an overview at the start; debug purposes only
    query = batch_lang.query('''
                                (separators) @sep
                            ''')

    # initialize string to append the output to
    out_string = "\n" + "=" * 80 + "\n"

    for capture in query.captures(tree.root_node):
        out_string += f"Found separator: {capture[0].text.decode(encoding)}\n"

    if stream == 'logging':
        logging.debug(out_string)
    elif stream == 'stdout':
        print(out_string)
    else:
        logging.warning(
            "Invalid value for stream parameter in query_variable_substitutions() specified. Hence,"
            "nothing will be printed.")
