==========================
command escaped 1$
==========================

e^c^h^o

---

(source_file
    (command
        (command_name)))

==========================
command escaped 2$
==========================

ass^o^c

---

(source_file
    (command
        (command_name)))

==========================
~ command separator 1$
==========================

echo((

---

;; This is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo` and the text is `((`
;; (source_file
;;     (command
;;         (command_name)
;;         (text)))

(source_file
    (command
        (command_name)))

==========================
~ command separator 2$
==========================

echo^((

---

;; in batch, the first ( belongs to command name because it's escaped, then a text!
;; This is the correct AST, but for simplicity we parse it as command name
;; the command name is `echo^(` and the text is `(`
;; (source_file
;;     (command
;;         (command_name)
;;         (text)))

(source_file
    (command
        (command_name)))

==========================
command separator 3$
==========================

;, ,;@echo

---

(source_file
    (command
        (command_name)))

==========================
variable as command 1$
==========================

%varname%

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable as command 2$
==========================

%PATH%

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable as command 3$
==========================

%varname %

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable as command 4$
==========================

%ŠŸ«†Ôø埃%

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable as command 5$
==========================

%abc def %

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable as command 6$
==========================

%a^b%

---

(source_file
    (command
        (command_name
            (variable_substitution))))

===========================
variable as command 7$
===========================

"a % ignored variable % b"

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable in command 1$
==========================

a%var%c

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable in command 2$
==========================

a^%var%c

---

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
variable in command 3$
==========================

a^%var^%c

---

(source_file
    (command
        (command_name
            (variable_substitution))))

===========================
string as command 1$
===========================

"%%Gabcdef%% & echo bye

---

;; we don't have a variable here, because `%%` will be escaped and printed as `%`,
;; and since this is an unclosed string, this whole line is considered as a command name

(source_file
    (command
        (command_name
            (for_variable))))

===========================
string as command 2$
===========================

"a b % c d

---

;; note that `%` is skipped here because it not a variable (followed by whitespace)
;; the text after it is not skipped because a matching/closing percent sign is missing!

(source_file
    (command
        (command_name)))

===========================
string as command 3$
===========================

">% invalid_var %<"

---

;; not a variable! `%` is followed by whitespace

(source_file
    (command
        (command_name
            (variable_substitution))))

==========================
demo 1$
==========================

ec%var_not_set%ho & rem comment

---

(source_file
    (command
        (command_name
            (variable_substitution)))
    (comment))
