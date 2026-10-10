========================================
if statements - variations
========================================

if exist example-file.bat (
  echo The file exists. & REM :: if exist file.bat ()
)
if cmdextversion 1 (ver)
if errorlevel 23234 goto l

---

;; the old `echo` command inside the IF statement was as follows:
;; `echo The file exists. & :: :: if exist file.bat ()`
;; note that the echo command contains a closing parenthesis which ends the IF statement, then on
;; the next line we have a single closing parenthesis which will be evaluated as a command name!
;; also note that i changed `::` to `REM` because `::` counts as a label inside a block...

(source_file
    (if_statement
        (condition_statement
            (unary_identifier_expression
                (text)))
        (command
            (command_name)
            (text))
        (comment))
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)))
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))))

========================================
if statements - comparison and %~
========================================

@if not 100 leq 0144 echo %~z1 %1

---

(source_file
    (if_statement
        (condition_statement
            (comparison_expression
                (text)
                (text)))
        (command
            (command_name)
            (text
                (variable_substitution)))))

========================================
if statements - unary_numerical_expression
========================================

if cmdextversion 01 echo "string"

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))))


========================================
if else statements - multiline variation
========================================

if exist example-file.bat (
  echo The file exists.
) else (
echo "The file does not exist."
)
if cmdextversion 1 (pause) else goto :label

---

(source_file
    (if_statement
        (condition_statement
            (unary_identifier_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text))))
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - if parentheses only
========================================

if cmdextversion 1 (echo "2") else echo "3"

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - both parentheses
========================================

if not cmdextversion 1 (echo "7") e^lse (
 echo "8"
)

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - hyperbolic separator usage
========================================

if not cmdextversion 1 (echo "9")=, ;;;==^e^l^s^e=;,(====,,;,;,;,,
===;,;,;,,echo="10"
		========;;;;,;;;;,,,,	   )

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - some more escaping
========================================

^if ^1 ^e^Q^u ^1 (echo 1
) ^e^l^s^e ^e^c^h^o ^2
^i^f ^n^o^t ^c^m^d^e^x^t^v^e^r^s^i^o^n ^1 (echo 1
) ^e^l^s^e ^e^c^h^o ^2

---

(source_file
    (if_statement
        (condition_statement
            (comparison_expression
                (text)
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text))))
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - no separator in front of else
========================================

if not cmdextversion 1 (echo "13")else (echo "14")

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))

========================================
if else statements - if command and closing if parenthesis on different lines
========================================

if not cmdextversion 1 (echo "15"
=========
;;,,,;,,;

)else (echo "16")

---

(source_file
    (if_statement
        (condition_statement
            (unary_numerical_expression
                (text)))
        (command
            (command_name)
            (text))
        (else_clause
            (command
                (command_name)
                (text)))))
