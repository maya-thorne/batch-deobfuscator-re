==========
set 1$
==========

set variable

---

(source_file
    (command
        (command_name)
        (text)))

==========
set 2$
==========

set /A variable=value

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 3$
==========

set variable=

---

(source_file
    (assignment
        (variable)
        (operator)))

==========
set 4$
==========

set /A variable=1+2

---

(source_file
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (value)
            (value))))

==========
set 5$
==========

set /A variable=value

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 6$
==========

set /A var=1+2*3/4-5

---

(source_file
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (binary_arithmetic_expression
                (value)
                (binary_arithmetic_expression
                    (binary_arithmetic_expression
                        (value)
                        (value))
                    (value)))
                (value))))

==========
set 7$
==========

set /a var=1+2*3/4-5

---

(source_file
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (binary_arithmetic_expression
                (value)
                (binary_arithmetic_expression
                    (binary_arithmetic_expression
                        (value)
                        (value))
                    (value)))
                (value))))

==========
set 8$
==========

set /P var=Enter value

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 9$
==========

set /p var=      Enter value to be assigned...^&%var1 %/$%var2% :: no comment

---

(source_file
    (assignment
        (variable)
        (operator)
        (value
            (variable_substitution)
            (variable_substitution))))

==========
set 10$
==========

set /p var=Type something... && echo foo

---

(source_file
    (and
        (assignment
            (variable)
            (operator)
            (value))
        (command
            (command_name)
            (text))))

==========
set 11$
==========

set var = 1

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 12$
==========

@set /a var = 1

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 13$
==========

set white space = va lue

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 14$
==========

set /P white space = Enter stuff

---

(source_file
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 15$
==========

set /a variable=6%%4

---

(source_file
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (value)
            (value))))

==========
set 16$
==========

set /a variable+=10
set /a variable-=5*1
set /a variable/=5/1/1+0
set /a variable*=3
set /a variable%%=2

---

(source_file
    (assignment
        (variable)
        (operator)
        (value))
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (value)
            (value)))
    (assignment
        (variable)
        (operator)
        (binary_arithmetic_expression
            (binary_arithmetic_expression
                (binary_arithmetic_expression
                    (value)
                    (value))
                (value))
            (value)))
    (assignment
        (variable)
        (operator)
        (value))
    (assignment
        (variable)
        (operator)
        (value)))

==========
set 17$
==========

set +v-a*r/i%%a b   l^e-=5
set /p +v-a*r/i%%a b    l^e/= Please don't enter Zero.

---

(source_file
    (assignment
        (variable
            (for_variable))
        (operator)
        (value))
    (assignment
        (variable
            (for_variable))
        (operator)
        (value)))

==========
set 18$
==========

set

---

(source_file
    (command
        (command_name)))

==========
set 19$
==========

set var%subst%iable =5

---

(source_file
    (assignment
        (variable
            (variable_substitution))
        (operator)
        (value)))
