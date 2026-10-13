"""This module contains the implementation of various code optimizations for
batch files."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# pylint: disable=logging-not-lazy
# pylint: disable=too-many-locals
# pylint: disable=too-many-branches
# pylint: disable=too-many-statements
# flake8: noqa

import logging
import utils


def constant_folding(src, encoding="utf-8"):
    """Given a batch file, applies constant folding as detected by the AST and
    returns the transformed batch file.

    :param src: a string representation of the batch source file
    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is "utf-8"

    :return: the processed string
    """

    parser, batch_lang = utils.create_parser()

    # src = 'set /A var=1+25*4/10-5'
    tree = parser.parse(src.encode(encoding))

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + tree.text.decode(encoding) + "\n" + "=" * 80)

    while True:
        query = batch_lang.query('''
            (arithmetic_expression (number) (number)) @expr
        ''')

        if len(query.captures(tree.root_node)) == 0:
            break

        for capture in query.captures(tree.root_node):
            logging.debug("optimizing:" + capture[0].text + "with ID" + capture[0].id)

            # we could have named `field`s in the grammar to make access better
            n1 = int(capture[0].children[0].text)
            op = capture[0].children[1].text.decode(encoding)
            n2 = int(capture[0].children[2].text)
            res = 0

            if op == '+':
                res = n1 + n2
            elif op == '-':
                res = n1 - n2
            elif op == '*':
                res = n1 * n2
            elif op == '/':
                res = n1 / n2

            # convert to int since floats aren't supported in our grammar
            res = int(res)

            startb = capture[0].start_byte
            startp = capture[0].start_point
            endb = capture[0].end_byte
            endp = capture[0].end_point
            update_len = len(str(res))

            src = src[:startb] + str(res) + src[endb:]

            logging.debug("BEFORE:" + tree.text.decode(encoding))

            tree.edit(
                start_byte=startb,
                old_end_byte=endb,
                new_end_byte=endb + update_len,
                start_point=startp,
                old_end_point=endp,
                new_end_point=(endp[0], endp[0] + update_len),
            )

            tree = parser.parse(src.encode(encoding), tree)

            logging.debug("AFTER:" + tree.text.decode(encoding) + "\n" + "-" * 80)

    out_str = tree.text.decode(encoding)

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + out_str + "\n" + "=" * 80)

    return out_str
