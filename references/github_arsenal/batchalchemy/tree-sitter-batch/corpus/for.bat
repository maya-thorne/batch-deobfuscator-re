=====================
for loop counting up
=====================

fOr /L %%G IN (1,1,5) DO echo %%G

---

(source_file
    (for_statement
        (text)
        (for_variable)
        (text)
        (text)
        (text)
        (command
            (command_name)
            (text
                (for_variable)))))

========================================
for statements - one liners
========================================

for %%i in ("C:\Windows\system32\*.exe") do @echo %%i
for /r /d %%i in (*) do @if %%~zi geq 1000000 echo %%~zi %%i

---

(source_file
    (for_statement
        (for_variable)
        (text)
        (command
            (command_name)
            (text
                (for_variable))))
    (for_statement
        (text)
        (for_variable)
        (text)
        (if_statement
            (condition_statement
                (comparison_expression
                    (for_variable)
                    (text)))
        (command
            (command_name)
            (text
                (for_variable)
                (for_variable))))))

========================================
for statements - l-switch empty bracket
========================================

for /l %%i in () do @echo %var%

---

(source_file
    (for_statement
        (text)
        (for_variable)
        (command
            (command_name)
            (text
                (variable_substitution)))))

========================================
for statements - options w/ backquotes
========================================

for /f "usebackq tokens=*" %%i in (`dir /b /a-d-h`) do @echo %%~nxai

---

(source_file
    (for_statement
        (text)
        (for_variable)
        (text)
        (command
            (command_name)
            (text
                (for_variable)))))

========================================
for statements - some escaping
========================================

^f^O^r ^/^L ^%%G ^I^N (^1,^1,^5) ^D^O ^e^c^h^o ^%%G
---

(source_file
    (for_statement
        (text)
        (for_variable)
        (text)
        (text)
        (text)
        (command
            (command_name)
            (text
                (for_variable)))))
