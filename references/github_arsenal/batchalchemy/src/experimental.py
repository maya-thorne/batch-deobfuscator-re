"""This module contains experimental functions that are not meant to be used
during production and are only meant for testing and demonstration purposes."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# pylint: disable=logging-not-lazy
# flake8: noqa

import logging

import utils


def modify_nodes(encoding="utf-8"):
    """Test function meant to experiment with tree-sitter's node traversing.
    This function can be ignored.

    :param encoding: the encoding string to be used within ``string.decode()`` commands; default is *"utf-8"*
    :return: None
    """

    parser, _ = utils.create_parser()

    # the goal of this function is to insert new nodes between `command4` and `command5` and to
    # remove the comment
    src = '''
        command 1
        command 2
        command 3
        :: this is a comment to be removed
        command 4
        command 5
    '''
    tree = parser.parse(src.encode(encoding))

    print("=" * 80)
    print("START:", tree.text.decode(encoding))
    print("=" * 80)
    print()

    comment = tree.root_node.children[3]

    startb = comment.start_byte
    startp = comment.start_point
    endb = comment.end_byte
    endp = comment.end_point

    print(startb, startp, endb, endp)

    src = src[:startb] + src[endb + 1:]

    tree.edit(
        start_byte=startb,
        old_end_byte=endb,
        # we subtract the length of the comment and the newline
        new_end_byte=(endb - len(comment.text) - 1),
        start_point=startp,
        old_end_point=endp,
        # assuming the comment has a sibling, we can use its end point
        new_end_point=(startp[0] - 1, comment.prev_sibling.end_point[1]),
    )

    tree = parser.parse(src.encode(encoding), tree)

    n1 = tree.root_node.children[3]
    n2 = tree.root_node.children[4]

    src = src[:n1.end_byte] + "new_command\n" + src[n2.start_byte:]

    tree.edit(
        start_byte=n1.end_byte,
        old_end_byte=n2.start_byte,
        new_end_byte=n2.start_byte + len("new_command\n"),
        start_point=n1.end_point,
        old_end_point=n2.start_point,
        new_end_point=(n1.end_point[0], n1.end_point[1] + len("new_command\n")),
    )

    tree = parser.parse(src.encode(encoding), tree)

    print()
    print("=" * 80)
    print("END:", tree.text.decode(encoding))
    print("=" * 80)


# pylint: disable=dangerous-default-value
def variable_expander(src, encoding="utf-8", env={}):
    """Test function meant to experiment with variable substitution in batch
    files.

    This function is
    a rewrite of the function `variable_substitution` in the `deobfuscator` module.
    """
    parser, batch_lang = utils.create_parser()

    logging.debug("\n" + "=" * 80 + "\nSTART:\n" + src + "\n" + "=" * 80)

    def variable_substitution_helper(src, env):
        print("...")
        # sleep(1)
        tree = parser.parse(src.encode(encoding))

        for capture in batch_lang.query('''
            (assignment
                (variable)
                (operator)
                (value)) @assign

            (assignment
                (variable)
                (operator)) @unassign

            (variable_substitution) @var
        ''').captures(tree.root_node):
            print('!!!', capture[0].text.decode())

            match capture[1]:
                case "assign":
                    print("1")

                    if len(
                            batch_lang.query('''
                        (variable_substitution) @var
                    ''').captures(capture[0])):
                        continue

                    env[capture[0].children[0].text.decode().lower(
                    )] = capture[0].children[2].text.decode()

                case "unassign":
                    print("2")
                    if capture[0].child_count == 2:
                        env.pop(capture[0].children[0].text.decode(), None)

                case "var":
                    print("3")
                    var = capture[0].text.decode(encoding).lower()
                    startb = capture[0].start_byte
                    endb = capture[0].end_byte

                    if not var[1:-1] in env:
                        src = src[:startb] + src[endb:]
                    else:
                        src = src[:startb] + env[var[1:-1]] + src[endb:]

                    return True, src

        return False, src

    while True:
        print("---")
        # NOTE: env is passed by reference, so it is updated in the function whereas src is
        # redefined in the function
        bb, src = variable_substitution_helper(src, env)
        if not bb:
            break

    print("END:", src)
    print("END:", env)
    return src
