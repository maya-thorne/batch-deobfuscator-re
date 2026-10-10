// Precedence order:
const PREC = {
    LOWERED: -1,
    UPDATE: 0,
    NORMAL: 0,
    HEIGHTENED: 1,
    THEN: 1,
    ADD_SUB: 1,
    MUL_DIV: 2,
    PIPELINE: 2,
    AND: 3,
    OR: 3,
};


module.exports = grammar({
    name: 'batch',

    conflicts: $ => [
        [$._statement]
    ],

    // scan for the basic building tokens of the language
    // see Creating Parsers/Keyword Extraction sections on tree-sitter
    word: $ => $.identifier,

    // tokens to skip
    extras: $ => [
        /[;,=@\s\f\uFEFF\u2060\u200B]/,
    ],

    // don't change the order of the rules without updating the order in the scanner too!
    // we'll have the convention of using two underscores for rules that are external
    // externals currently not used, since we went to a Python only approach
    externals: $ => [
        // $.__variable,
        // $.__variable_for,
        // $.__variable_parameter,
        // $.__text_chunk,
        // $.__command_name_chunk,
        // $.__command_name_end,
        // $.__block_start,
        // $.__block_end,
        // $.__comment,
        // $.__error_recovery,
    ],

    rules: {
        ////////////////////////////////////////
        // Main
        ////////////////////////////////////////

        // repeat also allows for empty files
        source_file: $ => repeat(seq(
            $._statement,
        )),

        _statement: $ => prec.left(seq(
            choice(
                $.comment,
                $._assignment,
                $.command,
                $.if_statement,
                $.for_statement,
                $.pipeline,
                $._then,
                $.and,
                $.or,
                $.label_definition,
                // $.redirect_statement,
            ),
            optional($._terminator),
        )),

        ////////////////////////////////////////
        // Statements
        ////////////////////////////////////////

        command: $ => prec.right(seq(
            repeat($.redirection),

            $.command_name,

            optional(seq(
                $._separators,
                optional($.text),

                repeat(seq(
                    $.redirection,
                    optional($.text),
                )),
            )),
        )),

        if_statement: $ => seq(
            addCaretToRegExp(caseInsensitive('if').source),
            optional(addCaretToRegExp(caseInsensitive('not').source)),
            $.condition_statement,
            choice(
                seq(
                    '(',
                    repeat($._statement),
                    // given higher precedence to fix cases in which the parenthesis was consumed by text
                    token(prec(PREC.HEIGHTENED, ')')),
                    // note that the parenthesis for if is necessary when paired with else
                    optional($.else_clause),
                ),
                $._statement,
            )
        ),

        else_clause: $ => seq(
            addCaretToRegExp(caseInsensitive('else').source),
            choice(
                seq(
                    '(',
                    repeat($._statement),
                    token(prec(PREC.HEIGHTENED, ')')),
                ),
                $._statement,
            ),
        ),

        condition_statement: $ => choice(
            $.unary_identifier_expression,
            $.unary_numerical_expression,
            $.comparison_expression,
        ),

        unary_numerical_expression: $ => seq(
            choice(
                addCaretToRegExp(caseInsensitive('errorlevel').source),
                addCaretToRegExp(caseInsensitive('cmdextversion').source),
            ),
            alias($.number, $.text),
        ),

        unary_identifier_expression: $ => seq(
            choice(
                addCaretToRegExp(caseInsensitive('defined').source),
                addCaretToRegExp(caseInsensitive('exist').source),
            ),
            choice(
                seq(
                    '"',
                    repeat(choice(
                        alias($.identifier, $.text),
                        $._generic_variable,
                    )),
                    '"',
                ),
                choice(
                    alias($.identifier, $.text),
                    $._generic_variable,
                ),
            ),
        ),

        for_statement: $ => seq(
            addCaretToRegExp(caseInsensitive('for').source),
            optional(alias($.text_no_for_variable, $.text)),
            $.for_variable,
            token(addCaretToRegExp(caseInsensitive('in').source)),
            '(',
            optional(choice(
                seq('`', alias($.text_for_parenthesis, $.text), '`'),
                seq(alias($.text_for_parenthesis, $.text), repeat(seq(',', alias($.text_for_parenthesis, $.text)))),
            )),
            ')',
            addCaretToRegExp(caseInsensitive('do').source),
            choice(
                seq(
                    '(',
                    repeat($._statement),
                    ')',
                ),
                seq(
                    $._statement,
                )
            )
        ),

        label_definition: $ => prec.left(seq(
            ':',
            $._label_name,
            optional(seq(
                alias($.text, $.comment),
            )),
            $._terminator,
        )),

        _assignment: $ => prec.right(seq(
            choice(
                alias($._assignment_set, $.command),
                alias($._assignment_set_var, $.command),
                alias($._assignment_set_var_no_value, $.assignment),
                alias($._assignment_set_var_value, $.assignment),
                alias($._assignment_set_var_arith_value, $.assignment),
                alias($._assignment_set_var_prompt_value, $.assignment),
            ),
            optional($._terminator),
        )),

        _assignment_set: $ => seq(
            alias(addCaretToRegExp(caseInsensitive('set').source), $.command_name),
        ),

        _assignment_set_var: $ => seq(
            alias(addCaretToRegExp(caseInsensitive('set').source), $.command_name),
            alias($.variable, $.text),
        ),

        _assignment_set_var_no_value: $ => seq(
            addCaretToRegExp(caseInsensitive('set').source),
            $.variable,
            alias(token.immediate('='), $.operator),
        ),

        _assignment_set_var_value: $ => prec(2, seq(
            addCaretToRegExp(caseInsensitive('set').source),
            $.variable,
            alias(token.immediate('='), $.operator),
            alias($.text, $.value),
        )),

        _assignment_set_var_arith_value: $ => prec(3, seq(
            addCaretToRegExp(caseInsensitive('set').source),
            addCaretToRegExp(caseInsensitive('/a').source),
            $.variable,
            alias(token.immediate(choice(
                '=',
                '+=',
                '-=',
                '*=',
                '/=',
                '%%=',
            )), $.operator),
            choice(
                $._value,
            ),
        )),

        _assignment_set_var_prompt_value: $ => prec(3, seq(
            addCaretToRegExp(caseInsensitive('set').source),
            addCaretToRegExp(caseInsensitive('/p').source),
            $.variable,
            alias(token.immediate('='), $.operator),
            alias($.text, $.value),
        )),


        ////////////////////////////////////////
        // Expressions (for assignments)
        ////////////////////////////////////////


        _value: $ => choice(
            alias(/\d+/, $.value),
            alias(/0x[0-9a-f]+/, $.value),
            alias(/0[0-8]+/, $.value),
            alias(/[a-zA-Z]+/, $.value),
            $.binary_arithmetic_expression,
        ),

        binary_arithmetic_expression: $ => choice(
            prec.left(PREC.ADD_SUB, seq($._value, '+', $._value)),
            prec.left(PREC.ADD_SUB, seq($._value, '-', $._value)),
            prec.left(PREC.MUL_DIV, seq($._value, '*', $._value)),
            prec.left(PREC.MUL_DIV, seq($._value, '/', $._value)),
            prec.left(PREC.MUL_DIV, seq($._value, '%%', $._value)),
        ),

        ////////////////////////////////////////
        // Operators
        ////////////////////////////////////////

        pipeline: $ => prec.left(PREC.PIPELINE, seq($._statement, token('|'), $._statement)),

        _then: $ => prec.left(PREC.THEN, seq($._statement, token('&'), $._statement)),

        and: $ => prec.left(PREC.AND, seq($._statement, token('&&'), $._statement)),

        or: $ => prec.left(PREC.OR, seq($._statement, token('||'), $._statement)),

        comparison_expression: $ => seq(
            choice(
                seq(
                    '"',
                    repeat(choice(
                        $._generic_variable,
                        alias($.number, $.text),
                        $._literal,
                    )),
                    '"',
                ),
                choice(
                    $._generic_variable,
                    alias($.number, $.text),
                    $._literal,
                ),
            ),
            choice(
                addCaretToRegExp('=='),
                addCaretToRegExp(caseInsensitive('equ').source),
                addCaretToRegExp(caseInsensitive('neq').source),
                addCaretToRegExp(caseInsensitive('lss').source),
                addCaretToRegExp(caseInsensitive('leq').source),
                addCaretToRegExp(caseInsensitive('gtr').source),
                addCaretToRegExp(caseInsensitive('geq').source),
            ),
            choice(
                seq(
                    '"',
                    repeat(choice(
                        $._generic_variable,
                        alias($.number, $.text),
                        $._literal,
                    )),
                    '"',
                ),
                choice(
                    $._generic_variable,
                    alias($.number, $.text),
                    $._literal,
                ),
            ),
        ),

        redirection: $ => seq(
            optional(/\d/),
            alias(token.immediate(choice('<', '>', '>>', '<&', '>&')), $.operator),
            alias(choice(
                token(seq('"', /[^\r\n"]+/, '"')),
                /[^"\s:|&<>]+/,
            ), $.text),
        ),

        ////////////////////////////////////////
        // Types
        ////////////////////////////////////////

        _generic_variable: $ => choice(
            $.variable_substitution,
            $.for_variable,
            $.parameter_variable,
        ),

        _generic_variable_no_for_variable: $ => choice(
            $.variable_substitution,
            $.parameter_variable,
        ),

        for_variable: _ => token(seq(
            '%%',
            optional(seq(
                '~',
                /[a-zA-Z$]+/,
            )),
            /[a-zA-Z]/
        )),
        variable_substitution: _ => /%[^0-9*%][^%]*%/,
        parameter_variable: _ => token(seq(
            '%',
            optional(seq(
                '~',
                /[a-zA-Z$]+/,
            )),
            /[0-9*]/,
        )),

        text: $ => prec.right(repeat1(choice(
            $._quoted_string,
            $._unquoted_string,
            $._escape_sequence,
            $._generic_variable,
            /\d+/,
            '%',
        ))),

        text_for_parenthesis: $ => prec.right(repeat1(choice(
            $._quoted_string_for_parenthesis,
            $._unquoted_string_for_parenthesis,
            $._escape_sequence,
            $._generic_variable,
            '%',
        ))),

        text_no_for_variable: $ => prec.right(repeat1(choice(
            $._quoted_string,
            $._unquoted_string,
            $._escape_sequence,
            $._generic_variable_no_for_variable,
            '%',
        ))),

        _quoted_string: $ => seq(
            '"',
            repeat(choice(
                /[^\r\n"%]+/,
                $._generic_variable,
                token('%'),
            )),
            choice(
                '"',
                /[\r\n]/,
            ),
        ),

        // only difference between this and normal _quoted_string is that this excludes parenthesis
        // and comma characters
        _quoted_string_for_parenthesis: $ => seq(
            '"',
            repeat(choice(
                /[^\r\n()"%]+/,
                $._generic_variable,
                token('%'),
            )),
            choice(
                '"',
                /[\r\n]/,
            ),
        ),

        _unquoted_string: _ => /[^"&|><%^\s0-9][^"&|><,%^\r\n0-9]*/,

        // only difference between this and normal _quoted_string is that this excludes parenthesis
        // and comma characters
        _unquoted_string_for_parenthesis: _ => /[^"&|><,()%^\s][^"&|><,()%^\r\n]*/,

        _unquoted_string_assignment: _ => /[^"&|><,=%^\s][^\r\n\f\v,;=&|<>%"^]*/,

        _escape_sequence: _ => prec(PREC.HEIGHTENED, choice(/\^[^%]/, '^')),

        _literal: $ => alias($.identifier, $.text),

        _label_name: _ => /[^:;,=+\s]+/,

        number: _ => prec.left(repeat1(
            seq(
                optional('^'),
                /\d+/,
            )
        )),

        // keep this public! upon successful parsing we shouldn't see any of these
        identifier: _ => /[^\s!@%^&()+*\\=\[\]:"|<>\/?`]+/, // " to fix syntax highlighting

        command_name: $ => prec.right(repeat1(prec.right(choice(
            $._quoted_string,
            seq(
                // assumption: command_names will only call local files that do not contain closing parenthesis
                /[^\s)"&|<>%^,;=:@]/,
                /[^\s)"&|<>%^,;=:]*/,
                /[^\s)"&|<>%^,;=]*/, // " to fix syntax highlighting
            ),
            $._generic_variable,
            /\^[^%\s]/,
            '^',
            '%',
        )))),

        variable: $ => prec.right(seq(
            /[^/&|<>\s,;="][^\r\n\f\v,;=&|<>%"^]+/,
            repeat(choice(
                $._unquoted_string_assignment,
                $._quoted_string,
                $._escape_sequence,
                $._generic_variable,
                '%',
            ))
        )),
        variable1: $ => prec.right(repeat1(/[^/\s,;=&|<>"][^\r\n\f\v,;=&|<>]+/)),

        comment: _ => token(choice(
            seq(
                caseInsensitive('rem'),
                choice(
                    / [^\r\n]*/,
                    token.immediate(/\r?\n/),
                ),
            ),
            seq(
                '::',
                /[^\r\n]*/,
            ),
        )),

        // the tokens `=;,` are considered whitespace if not quoted
        _separators: _ => token.immediate(/[ \t;=,]+/),

        // currently used for separation of commands
        _terminator: _ => token(/\r?\n/),
    }
});


function caseInsensitive(keyword) {
    return new RegExp(keyword
        .split('')
        .map(letter => `[${letter}${letter.toUpperCase()}]`)
        .join('')
    )
}

function addCaretToRegExp(pattern) {
    return new RegExp(pattern
        .replace(/\[/g, '\\^?[')
    )
}