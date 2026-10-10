===========================
echo word 1$
===========================

@;,=@echo

---

(source_file
    (command
        (command_name)))

===========================
echo word 2$
===========================

echo on

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 3$
===========================

echo off

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 4$
===========================

echo on the beach

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 5$
===========================

echo off ; echo on

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 6$
===========================

echo nice ^& easy

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 7$
===========================

echo salary is ^> commision ^| vertical

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 8$
===========================

echo:hello

---

(source_file
    (command
        (command_name)))

===========================
echo word 9$
===========================

echo ^G

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 10$
===========================

echo this shouldn't be a :: comment

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo word 11$
===========================

echo asdf^ zxcv^&qwer

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo string 1$
===========================

echo "hello"

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo string 2$
===========================

echo "nice & easy"

---

(source_file
    (command
        (command_name)
        (text)))


===========================
echo string 3$
===========================

echo "%%%%"

---

;; this will output `"%%"`

(source_file
    (command
        (command_name)
        (text)))


===========================
echo string 4$
===========================

echo ">% invalid_var %<"

---

;; not a variable! `%` is followed by whitespace

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo string 5$
===========================

echo "a & echo bye

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo string 6$
===========================

echo "%not_var

---

;; note that `%` won't be printed!

(source_file
    (command
        (command_name)
        (text)))

===========================
echo string 7$
===========================

echo " a % % %%Gabcdef%% & echo bye

---

;; we have a for variable here: `%%n`

(source_file
    (command
        (command_name)
        (text
            (variable_substitution)
            (for_variable))))

===========================
echo string 8$
===========================

echo a%"

---

;; `%` won't be printed!

(source_file
    (command
        (command_name)
        (text)))

===========================
echo variable 1$
===========================

echo %var%

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
~ echo variable 2$
===========================

echo(%var%

---

;; this is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo` and the text is `(%var%`
;; (source_file
;;     (command
;;         (command_name)
;;         (text
;;             (variable_substitution))))

(source_file
    (command
        (command_name
            (variable_substitution))))

===========================
echo variable 3$
===========================

echo % invalid var %

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 4$
===========================

echo %1not_var% & echo bye

---

;; `%1` is a script paramater! if undefined, the output will be `b` only!
;; also, variables can't start with a number!

(source_file
    (command
        (command_name)
        (text
            (parameter_variable)))
    (command
        (command_name)
        (text)))

===========================
echo variable 5$
===========================

echo %one&var% & echo bye

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution)))
    (command
        (command_name)
        (text)))

===========================
echo variable 6$
===========================

echo "a %var" % c

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 7$
===========================

echo a %var" % c

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 8$
===========================

echo a % invalid_var" % c

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 9$
===========================

echo "a %var%" & echo bye

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution)))
    (command
        (command_name)
        (text)))

===========================
echo variable 10$
===========================

echo a%var%b

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 11$
===========================

echo a % ignored variable % b

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 12$
===========================

echo "^%var%"

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo variable 13$
===========================

echo "^%var^%"

---

(source_file
    (command
        (command_name)
        (text
            (variable_substitution))))

===========================
echo delimiter 1$
===========================

echo off & echo on

---

(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text)))

===========================
echo delimiter 2$
===========================

echo 'hello & echo bye

---

(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text)))

===========================
echo delimiter 3$
===========================

echo a & echo b & echo c & echo d

---

(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text)))

===========================
echo delimiter 4$
===========================

echo first line & echo: & echo second line

---

(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name))
    (command
        (command_name)
        (text)))

===========================
echo delimiter 5$
===========================

echo "one" & echo "two" && echo "three"
echo "four"

---

(source_file
    (command
        (command_name)
        (text))
    (and
        (command
            (command_name)
            (text))
        (command
            (command_name)
            (text)))
    (command
        (command_name)
        (text)))

===========================
echo concat 1$
===========================

echo "hello""world"

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo concat 2$
===========================

echo b"a & echo bye

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo concat 3$
===========================

echo asdf" & echo bye

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 1$
===========================

echo /?

---

;; flag!
(source_file
    (command
        (command_name)
        (text)))

===========================
~ echo flag 2$
===========================

echo/ /?
EcHo\ /?
eChO= /?
ECHo+ /?
eCHO[ /?
EcHO] /?
eCHo; /?
ecHo: /?
EchO( /?
echo  /?
echo. /?

---

;; here we parse the first character after `echo` as part of the command, whereas it's actually part
;; of the text!
(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    ;; flag!
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    ;; flag!
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    ;; flag!
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text)))

===========================
~ echo flag 3$
===========================

echo/?

---

;; flag!
;; This is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo` and the text is `/?`
;; (source_file
;;     (command
;;         (command_name)
;;         (text)))

(source_file
    (command
        (command_name)))

===========================
~ echo flag 4$
===========================

echo:/?

---

;; This is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo` and the text is `:/?`
;; (source_file
;;     (command
;;         (command_name)
;;         (text)))

(source_file
    (command
        (command_name)))

===========================
~ echo flag 5$
===========================


echo/? ignored text

---

;; flag!
;; here we parse `/?` as part of the command, whereas it's actually part of the text!
(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 6$
===========================

echo /? & echo off

---

;; flag!
(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text)))

===========================
echo flag 7$
===========================

echo hello /?

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 8$
===========================

echo /P /?

---

;; flag! `/P` won't be printed!

(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 9$
===========================

echo /P hello /?

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 10$
===========================

echo hello /P /?

---

(source_file
    (command
        (command_name)
        (text)))

===========================
~ echo flag 11$
===========================

echo/P /?

---

;; flag!
;; here we parse `/P` as part of the command, whereas it's actually part of the text!
(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 12$
===========================

echo:a /?

---

(source_file
    (command
        (command_name)
        (text)))

===========================
~ echo flag 13$
===========================

echo/a /?

---

;; flag!
;; here we parse `/a` as part of the command, whereas it's actually part of the text!
(source_file
    (command
        (command_name)
        (text)))

===========================
echo flag 14$
===========================

echo=/?

---

;; flag!
(source_file
    (command
        (command_name)
        (text)))

===========================
~ echo flag 15$
===========================

echo(/?

---

;; This is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo` and the text is `(/?`
;; (source_file
;;     (command
;;         (command_name)
;;         (text)))

(source_file
    (command
        (command_name)))

===========================
echo flag 16$
===========================

echo,/?

---

;; flag!
(source_file
    (command
        (command_name)
        (text)))

===========================
echo complex 1$
===========================

echo "hello" world "without" quotes

---

(source_file
    (command
        (command_name)
        (text)))

===========================
echo complex 2$
===========================

echo "my" % new %var% is "%var%"

---

;; there are no *valid* variables in the string! when `%` is followed by a whitespace, batch ignores
;; everything until a closing percent sign is found. if there's no closing percent sign, the first
;; percent sign is used as an escape character, check other examples: `11. echo variable` and
;; `5. echo complex`. However, we'll still parse them as variables

(source_file
    (command
        (command_name)
        (text
            (variable_substitution)
            (variable_substitution))))

===========================
echo complex 3$
===========================

echo "a %var1" % c %var2% d "e % f" g % h "%var3%" i

---

;; a variable may contain a quotation mark! assuming the variables are set to `X`, `Y`, `Z`
;; respectively, the output will be: `"a X c Y d "e h "Z" i`

(source_file
    (command
        (command_name)
        (text
            (variable_substitution)
            (variable_substitution)
            (variable_substitution)
            (variable_substitution))))

===========================
echo complex 4$
===========================

echo " a % % %%Gabcdef%% & echo %var% bye " & echo howdy

---

;; we have a for variable here: `%%n`
(source_file
    (command
        (command_name)
        (text
            (variable_substitution)
            (for_variable)
            (variable_substitution)))
    (command
        (command_name)
        (text)))

===========================
echo complex 5$
===========================

echo a b % c d

---

;; note that `%` is skipped here because it not a variable (followed by whitespace)
;; the text after it is not skipped because a matching/closing percent sign is missing!

(source_file
    (command
        (command_name)
        (text)))
