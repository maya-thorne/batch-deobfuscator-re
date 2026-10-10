==========
label 1$
==========

:label

---

(source_file
    (label_definition))

==========
label 2$
==========

@:label

---

(source_file
    (label_definition))

==========
label 3$
==========

:actual_label_name not_part_of_label_name

---

(source_file
    (label_definition
        (comment)))

==========
label 4$
==========

:actual_label_name:not_part_of_label_name

---

(source_file
    (label_definition
        (comment)))

==========
label 5$
==========

:┌(ಠ_ಠ)┘ ┌(ಠ_ಠ)┘

---

(source_file
    (label_definition
        (comment)))

==========
label 6$
==========

:label :not_a_label
::not_a_label :still_not_a_label

---

(source_file
    (label_definition
        (comment))
    (comment))

==========
label 7$
==========

: 		label

---

(source_file
    (label_definition))

==========
label 8$
==========

: 		,;=;=,label

---

(source_file
    (label_definition))

==========
label 9$
==========

: 		,;=;=,label,;=;=, 		:

---

(source_file
    (label_definition
        (comment)))
