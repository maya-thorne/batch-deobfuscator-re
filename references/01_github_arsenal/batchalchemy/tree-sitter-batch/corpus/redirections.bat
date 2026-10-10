===========================
redirection 1$
===========================

echo redirect this to > file

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))))

===========================
redirection 2$
===========================

echo redirect this to >"file with spaces"

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))))

===========================
redirection 3$
===========================

echo redirect this to > file1 and this to > file2

---

;; note that the output is written to `file2` only, but the first redirection isn't part of the
;; string written to the file!

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))
        (text)
        (redirection
            (operator)
            (text))))

===========================
redirection 4$
===========================

echo redirect this to > file and more text

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))
        (text)))

===========================
redirection 5$
===========================

echo redirect this to 2>&1 further text

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))
        (text)))

===========================
redirection 6$
===========================

echo redirect this to <&2 further text

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))
        (text)))

===========================
redirection 7$
===========================

echo redirect this to 2> further text

---

(source_file
    (command
        (command_name)
        (text)
        (redirection
            (operator)
            (text))
        (text)))

===========================
redirection 8$
===========================

2<&1 echo

---

(source_file
    (command
        (redirection
            (operator)
            (text))
        (command_name)))
