"""This module contains functions to deobfuscate batch files."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# pylint: disable=logging-not-lazy
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# flake8: noqa

from time import sleep
import logging
import os
import re

import formatting
import utils


def command_name_cleaner(src, encoding="utf-8"):
    """Removes caret characters (meant for escaping) from command names as
    detected by the AST, given a batch file.

    :param src: a string representation of the batch source file
    :param encoding: string encoding
    :return: the processed string
    """

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(src.encode(encoding))

    logging.debug('\n' + '=' * 80 + '\nSTART:\n' + tree.text.decode(encoding) + '\n' + '=' * 80)

    cmd_name_cnt = None

    while True:
        query = batch_lang.query('''
            (command_name) @cmd
        ''')

        if cmd_name_cnt == 0:
            break

        cmd_name_cnt = len(query.captures(tree.root_node))

        for capture in query.captures(tree.root_node):
            logging.debug("optimizing: " + capture[0].text.decode(encoding))
            name = capture[0].text.decode(encoding)

            if '^' in name:
                name = re.sub(r'\^', '', name)

            else:
                cmd_name_cnt -= 1
                continue

            startb = capture[0].start_byte
            startp = capture[0].start_point
            endb = capture[0].end_byte
            endp = capture[0].end_point

            update_len = len(name) + 1

            src = src[:startb] + name + src[endb:]

            tree.edit(
                start_byte=startb,
                old_end_byte=endb,
                new_end_byte=endb + update_len,
                start_point=startp,
                old_end_point=endp,
                new_end_point=(endp[0], endp[0] + update_len),
            )

            tree = parser.parse(src.encode(encoding), tree)

            logging.debug("-" * 80)

            cmd_name_cnt = len(query.captures(tree.root_node))
            break

    logging.debug("\n" + "=" * 80 + "\nEND:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    return src


def variable_substitution(src,
                          encoding="utf-8",
                          env={},
                          expand_local=False,
                          expand_env=False,
                          placeholder=b'#$#'):
    """Given an input batch file, this function removes all unset variables
    enclosed in parentheses, given the current environment and gives options to
    expand locally set variables or variables which are set in the current
    environment. Locally set variables describe variables that have been set in
    the input batch file up until the current processing step. Whether to
    expand these types of variables with their value or to leave them as is can
    be decided by the two flags expand_local and expand_env individually.

    :param src: a string representation of the batch source file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is *"utf-8"*
    :param env: a dictionary of environment variables to be used for variable substitution. Note that this dictionary
        is updated during the processing of the batch file, so that it contains all variables that have been set in the
        batch file up until the current processing step.
    :param expand_local: bool flag that specifies whether variables that were assigned by a `set` command should be
        expanded or not. If set to True, note that only the assigned variable-value pairs that have occurred in
        previously processed ASTs will be taken into account. Caution! This means, that in case of non-linear code
        execution, this expansion is not guaranteed to work. Defaults to *False*.
    :param expand_env: bool flag that specifies whether variables that are set in the current environment should be
        expanded or not. If set to True, note that only the assigned variable-value pairs of the current list of
        environment variables will be taken into account. Also note that this has lower precedence concerning the
        order of substitution than the `expand_local` parameter. Caution! Due to the dynamics of environments, this
        expansion is not guaranteed to work. Defaults to *False*.
    :param placeholder: an ascii bytes literal that is used to temporarily mark variable positions; after all the
        querying is done, every single occurrence of it gets replaced by the original variable substitution. Note
        that this parameter is only used in case that any of the `expand_local` or `expand_env` flags are set to
        True. Caution! The value of placeholder should not occur in src anywhere. Defaults to *b'#$#'*
    :return: the processed string
    """

    out_string = src

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(out_string.encode(encoding))

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    while True:
        # The while loop basically does the following steps:
        #  1. query for assignments in the source file
        #  2. update list of assignments
        #  3. query for variables in the batch
        #  4. update the batch by processing variable substitutions one by one
        #  5. update / reparse the AST
        #  6. repeat / go to step 1.

        # if desired, use the following debugging code line to show the AST after each step
        # logging.debug(formatting.format_sexp(tree.root_node.sexp()))

        # query variables which are set in this batch file to make list of variables which should not be gotten rid of
        query_new_variables = batch_lang.query('''
            (assignment
                (variable) @varname
                (operator)
                (value) @val)
        ''')

        # this for loop uses the query above to update the dictionary new_assignment which is used for variable
        #  substitution of variables which are set inside the batch
        for set_query_capture in query_new_variables.captures(tree.root_node):
            # if current capture corresponds to a newly set variable name within the set command (/assignment)
            if set_query_capture[1] == "varname":
                new_variable_as_str = set_query_capture[0].text.decode(encoding)
                # only set up a new key for the dict of new_assignment once per newly set variable_name
                if new_variable_as_str not in env:
                    logging.debug("Found set " + new_variable_as_str + " = ...")
                    logging.debug("Adding this to dictionary env.")
                    env[new_variable_as_str] = ""
            # if current capture corresponds to a newly set value for a variable within the set command (/assignment)
            elif set_query_capture[1] == "val":
                new_value_as_str = set_query_capture[0].text.decode(encoding)
                # only update the dict of new_assignment if value is not already up to date
                if not env[new_variable_as_str] == new_value_as_str:
                    logging.debug("Found set ... = " + new_value_as_str)
                    logging.debug("Updating this to dictionary env.")
                    # update (meaning to overwrite) current value of the dictionary at key=<last key that was captured>
                    env[new_variable_as_str] = new_value_as_str
            else:
                # This shouldn't happen at all.
                logging.warning("Found capture with unrecognized query-@tag.")

        logging.debug("Content of env:" + str(env))

        # now query for the variables which are meant to be expanded / erased
        query = batch_lang.query('''
                (variable_substitution) @var
        ''')

        # finish when nothing was captured anymore, meaning that no %variables% are left in the batch file
        if not query.captures(tree.root_node):
            break

        # note that we process the batch and the tree for just one capture in the for loop since we break after one step
        #  thus we can probably change this to ``capture = query.captures(tree.root_node)[0]`` and de-indent by four
        capture = query.captures(tree.root_node)[0]
        variable_as_str = capture[0].text.decode(encoding)
        logging.debug("Now substituting variable:" + variable_as_str)

        # keep in mind that this all starts at (0,0), unlike e.g. the Pycharm IDE, which starts at (1,1)
        startb = capture[0].start_byte
        startp = capture[0].start_point
        endb = capture[0].end_byte
        endp = capture[0].end_point

        # initialize a python variable, which describes the length of the environment variable which is to be
        #  substituted
        old_var_len = abs(endb - startb)

        # initialize a python variable, which describes the length of the value with which the variable will be
        #  replaced; in this way, it is usable by all three cases below
        new_var_len = 0

        # case that the variable has been set in the current batch file before thus replace it with its assigned val
        if variable_as_str[1:-1] in env:
            # case that we want to actually expand the locally set variable
            if expand_local:
                value = env[variable_as_str[1:-1]]
                # use local helper function to replace first occurrence of a variable with its value according to dict
                out_string = utils.replace_first_occurrence(out_string, variable_as_str, value)
                new_var_len = len(value.encode(encoding))

            # case that we do not want to expand the locally set variable; aka just mark it and restore it later
            else:
                # mark the variable with the placeholder instead of percent symbols; this way, tree-sitter temporarily
                #  ignores it
                # since we only get positional information of the byte representation, operate on bytes here
                out_bytes = out_string.encode(encoding)
                # replace % with placeholder (thus marking it)
                out_string = (out_bytes[:startb] + placeholder + out_bytes[startb + 1:endb - 1] +
                              placeholder + out_bytes[endb:]).decode(encoding)
                # note that leading and trailing % characters are replaced by one placeholder byte literal each
                new_var_len = (len(placeholder) * 2) + (old_var_len - 2)

        else:
            # get value of environment variable which is being considered right now
            exp_variable_as_string = os.path.expandvars(variable_as_str)

            # case that variable has neither a value in the current environment (os.path does not replace it in this
            #  case) nor in the env dictionary (it was not set in the current batch file before)
            if exp_variable_as_string == variable_as_str:
                # simply cut out the variable since it has no value
                # since we only get positional information of the byte representation, operate on bytes here
                out_bytes = out_string.encode(encoding)
                out_string = (out_bytes[:startb] + out_bytes[endb:]).decode(encoding)

            # case that the variable has an actual value in the current environment, thus it is replace-able and was
            #  not set in the current batch file so far (not part of the env dictionary)
            else:
                # case that we want to actually expand the variable which has a value in the current environment
                if expand_env:
                    # use local helper function to replace first occurrence of the var with its current environment val
                    out_string = utils.replace_first_occurrence(out_string, variable_as_str,
                                                                exp_variable_as_string)
                    new_var_len = len(exp_variable_as_string.encode(encoding))

                # case that we do not want to expand the variable; aka just mark it and restore it later
                else:
                    # mark the variable with the placeholder instead of percent symbols; this way, tree-sitter
                    #  temporarily ignores it
                    # since we only get positional information of the byte representation, operate on bytes here
                    out_bytes = out_string.encode(encoding)
                    # replace % with placeholder (thus marking it)
                    out_string = (out_bytes[:startb] + placeholder +
                                  out_bytes[startb + 1:endb - 1] + placeholder +
                                  out_bytes[endb:]).decode(encoding)
                    # note that leading and trailing % characters are replaced by one placeholder byte literal each
                    new_var_len = (len(placeholder) * 2) + (old_var_len - 2)

        # update the tree
        tree.edit(
            start_byte=startb,
            old_end_byte=endb,
            new_end_byte=endb - old_var_len + new_var_len,
            start_point=startp,
            old_end_point=endp,
            new_end_point=(endp[0], endp[1] - old_var_len + new_var_len),
        )

        # reparsing using the old tree, just for efficiency
        tree = parser.parse(out_string.encode(encoding), tree)

        logging.debug("\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    # cleaning step: replace placeholder with a percent character each, thus, restoring it to become a variable
    out_string = out_string.replace(placeholder.decode(encoding), "%")

    logging.debug("\n" + "=" * 80 + "\nEND:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    return out_string


def query_variable_assignments(src, encoding="utf-8", stream="logging"):
    """Given the current state of a batch file, query the file for any variable
    assignments which are detectable in the AST right now. Prints all found
    occurrences which follow the S-expression ``(assignment (variable)
    (value))``, either to stdout or on the logging DEBUG level, separated by
    newlines each.

    :param src: a string representation of the batch source file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is *"utf-8"*
    :param stream: a string that specifies the stream to which the list of found variables should be printed.
        Possible values are *"logging"* to log via root logger or *"stdout"* to print to standard output. Defaults
        to *"logging"*. Note that the logger's level must be set to ``logging.DEBUG`` to actually make the result
        visible.
    :return: None
    """

    parser, batch_lang = utils.create_parser()

    tree = parser.parse(src.encode(encoding))

    # query all occurrences of ``set variable = value`` found in batch to log an overview
    query = batch_lang.query('''
                                (assignment
                                    (variable)
                                    (value)) @ass
                            ''')

    # initialize string to append the output to
    out_string = out_string = "\n" + "=" * 80 + "\n"

    for capture in query.captures(tree.root_node):
        out_string += f"Found assignment: {capture[0].text.decode(encoding)}\n"

    if stream == 'logging':
        logging.debug(out_string)
    elif stream == 'stdout':
        print(out_string)
    else:
        logging.warning(
            "Invalid value for stream parameter in query_variable_assignments() specified. Hence,"
            "nothing will be printed.")
