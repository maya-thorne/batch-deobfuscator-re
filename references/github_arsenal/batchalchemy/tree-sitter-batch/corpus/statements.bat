========================================
Echo and comments
========================================

@echo off
echo helloworld :: some text
rem text7

---

(source_file
    (command
        (command_name)
        (text))
    (command
        (command_name)
        (text))
    (comment))

========================================
Echo multiple words
========================================

@echo off
echo hello world && echo "Hello world!"
rem text7

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
    (comment))



========================================
Terminators - Testing statements
========================================

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

========================================
Switches and attributes
========================================

dir /b /a-d-h

---

(source_file
    (command
        (command_name)
        (text)))

========================================
Basic conditional execution
========================================

echo "one" && echo 2 & echo three || echo "four"

---

(source_file
    (and
        (command
            (command_name)
            (text))
        (command
            (command_name)
            (text)))
    (or
        (command
            (command_name)
            (text))
        (command
            (command_name)
            (text))))

========================================
Simple pipelines
========================================

@dir *.txt | @more

---

(source_file
    (pipeline
        (command
            (command_name)
            (text))
        (command
            (command_name))))

========================================
Double pipeline & rem-String
========================================

find /V "Hello" "test.txt" | find /V "world" | find /V ".remedy"

---

(source_file
    (pipeline
        (pipeline
            (command
                (command_name)
                (text))
            (command
                (command_name)
                (text)))
        (command
            (command_name)
            (text))))
