==========
comment 1
==========

rem comment
REM comment
:: comment
::comment
REM echo off

---

(source_file
    (comment)
    (comment)
    (comment)
    (comment)
    (comment))

==========
comment 2
==========

:: asd

---

(source_file
    (comment))

==========
comment 3
==========

@;,;=,@::

---

(source_file
    (comment))

==========
comment 4
==========

echo afdjlkg rem asd

---

(source_file
    (command
        (command_name)
        (text)))

==========
comment 5
==========

rem asd
Rem asd
rEm asd
reM asd
REm asd
REM asd
ReM asd
reM asd

---

(source_file
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment))

==========
comment 6
==========

rem
Rem
rEm
reM
REm
REM
ReM
reM

---

(source_file
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment)
      (comment))
