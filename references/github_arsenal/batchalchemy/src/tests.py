"""This module contains test functions that are meant for testing and evaluation purposes."""

# pylint: disable=pointless-string-statement
# pylint: disable=line-too-long
# flake8: noqa

import shutil
from deobfuscator import *
from formatting import to_lower_case
import utils
import logging
import os


def test_baum1810_obfuscated_malware_samples():
    """This method tests the entirety of malware-files which are located in the
    baum1810-malware folder.

    Note: I did not git-add the zip file, since I don't know if it is illegal to upload that on the Uni Info GitLab?
    """
    path_to_malware = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts",
                                   "malware", "baum1810-malware")

    for filename in os.listdir(path_to_malware):
        # exclude tim's malware batch file and the zipped folder
        if filename.startswith("raw") or ".7z" in filename or "baum1810" in filename:
            logging.debug("Skipping file" + filename)
            continue

        with open(os.path.join(path_to_malware, filename), "r", encoding="utf-8") as f:
            # Fill the brackets for how many symbols the file's content should be deobfuscated, or remove number to
            #  fully process the files (but it takes ages on my computer xD)
            obfuscated_malware = (f.read())[:2000]
            logging.debug("Using variable_substitution() on file" + filename)
            # Print the malware's content after its variables being substituted
            print(variable_substitution(obfuscated_malware))

        input_ = input(
            f"File {filename} has been processed. Press N to exit or anything else to continue with the next file."
        )
        if input_ == "N":
            return


def test_to_lower_case():
    """Use this as a temporary testing functionality for the to_lower_case()
    function:

    string for testing purposes only; it addresses many of the tricky
    parts of lower casing the correct tokens only casting it to upper
    case is just to easily visualize which parts got lower cased by this
    function

    pipeline flawlessly  (thus after implementing removal of carets)
    """

    out_string = r"""iF eXISt eXAMPle-file.bat (
        eCHo The fILe eXiSts.
        ) ELsE (
        eCHo "The file does not EXIst."
        )
        fOr %%i iN ("C:\WinDOws\sYStem32\*.exe") DO @eChO %%I
        SET variable = not an existing value
        if %equ% equ %equ% (echo EXIST) :: tHis is A comMent
        :lLLllLLlL
        cmd%ACTUALLYSETVARIABLE%name /a ArguMents
    """.upper()
    print(to_lower_case(out_string, keywords=None))


def test_parser_correctness(encoding="utf8"):
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function first grabs all test files from the directory *eval-src* and parses them according to the Batch-
    parser. The resulting ASTs are written to a folder called *parsed*. Files that couldn't be parsed due to Unicode-
    DecodeErrors are put in a separate directory named *unicode-errors*. Lastly, all AST files which contain at least
    one of either of tree-sitter's main error keywords (ERROR, MISSING) are copied into a third directory named
    *eval_errors*.

    :param encoding: the encoding string to be used within ``string.encode()`` commands; default is *"utf-8"*
    :return: None
    """
    parser, batch_lang = utils.create_parser()

    # Set up paths and folders
    path_to_tests = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval-src")
    parsed_path = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "parsed")
    if not os.path.exists(parsed_path):
        os.makedirs(parsed_path)
    unicode_error_path = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "unicode_errors")
    if not os.path.exists(unicode_error_path):
        os.makedirs(unicode_error_path)
    error_directory = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval_errors")
    if not os.path.exists(error_directory):
        os.makedirs(error_directory)

    print("Starting with parsing all files...")
    for filename in os.listdir(path_to_tests):
        with open(os.path.join(path_to_tests, filename), "r") as f:
            # print(f"Parsing file: {filename}")
            try:
                file_content = f.read()
                parsed_content = parser.parse(file_content.encode(encoding))
                # ast = parsed_content.text.decode(encoding)
                # ast = format_s_exp(parsed_content.root_node.sexp())
                ast = parsed_content.root_node.sexp()

                # Write the AST to a new file
                output_filename = os.path.splitext(filename)[0] + "_AST.txt"
                output_dest = os.path.join(parsed_path, output_filename)
                with open(output_dest, "w") as output_file:
                    output_file.write(ast)
            except UnicodeDecodeError as e:
                print("UnicodeDecodeError occured: ", e)
                # Copying the file containing the UnicodeError to a new folder
                output_filename = os.path.splitext(filename)[0] + "_UNICODE_ERROR.bat"
                output_dest = os.path.join(unicode_error_path, output_filename)
                src = os.path.join(path_to_tests, filename)
                shutil.copyfile(src, output_dest)
    print("Parsing finished.")

    print("Now starting with finding parsed files containing errors...")
    error_files = []
    for filename in os.listdir(parsed_path):
        if filename.endswith("_AST.txt"):
            # print(f"Checking file: {filename}")
            file_path = os.path.join(parsed_path, filename)
            with open(file_path, 'r') as file:
                content = file.read()
                if any(keyword in content for keyword in ['ERROR', 'MISSING']):
                    error_files.append(filename)
    print("Successfully iterated over all files in search of errors.")

    print("Now starting with copying all files containing errors into a separate directory...")
    for filename in error_files:
        # print(f"Copying file: {filename}")
        src = os.path.join(parsed_path, filename)
        dest = os.path.join(error_directory, filename[:-4] + '_error.txt')
        shutil.copyfile(src, dest)
    print("Successfully copied all error files.")


def test_redirection():
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function counts how many files include an error related to grammar.js's redirection rule. The existance of this
    function is the result of manual analysis of error files and realizing that this concept in particular was worth
    taking a closer look at.

    Outputs the number of files which contain errors related to the parser's rule *redirection*.
    On top of that, all files in the directory *eval-errors* get marked by prepending a mark to their names
    (*redir_err_*).

    :param: None
    :return: None
    """
    count = 0
    error_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval_errors")
    for filename in os.listdir(error_dir):
        # print(f"Checking file: {filename} for unexpected redirections")
        file_path = os.path.join(error_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            if any(op in content for op in ['<', '>', '>>', '<&', '>&']):
                count += 1
                if "redir_err_" not in filename:
                    os.rename(file_path, os.path.join(error_dir, "redir_err_" + filename))

    print(f"{count} files include errors related to redirect operations.")


def test_missing_only():
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function counts how many files include an error related to tree-sitter's *MISSING* error keyword. The
    existance of this function is the result of manual analysis of error files and realizing that this concept in
    particular was worth taking a closer look at.

    Outputs the number of files which contain only errors related to tree-sitter's *MISSING* keyword, hinting at test
    cases where the parser probably works in a bit too rigid way.
    On top of that, all files in the directory *eval-errors* get marked by prepending a mark to their names
    (*missing_only_*).

    :param: None
    :return: None
    """
    count = 0
    error_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval_errors")
    for filename in os.listdir(error_dir):
        # print(f"Checking file: {filename} for only containing MISSING error keyword")
        file_path = os.path.join(error_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            if 'ERROR' not in content and 'MISSING' in content:
                count += 1
                if "redir_err_" not in filename and "missing_only_" not in filename:
                    os.rename(file_path, os.path.join(error_dir, "missing_only_" + filename))

    print(f"{count} files include errors related only to MISSING keyword.")


def test_either_missing_unexpected():
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function counts how many files include an error related to tree-sitter's *MISSING* or *UNEXPECTED* error
    keywords. The existance of this function is the result of manual analysis of error files and realizing that these
    concepts in particular was worth taking a closer look at.

    Outputs the number of files which contain either of the errors related to tree-sitter's *MISSING* or *UNEXPECTED*
    keywords, hinting at test cases where the parser probably works in a bit too rigid way.
    On top of that, all files in the directory *eval-errors* get marked by prepending a mark to their names
    (*miss_unexp_*).

    :param: None
    :return: None
    """
    count = 0
    error_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval_errors")
    for filename in os.listdir(error_dir):
        # print(f"Checking file: {filename} for only containing MISSING error keyword")
        file_path = os.path.join(error_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            if 'UNEXPECTED' in content or 'MISSING' in content:
                count += 1
                if "redir_err_" not in filename and "miss_unexp_" not in filename:
                    os.rename(file_path, os.path.join(error_dir, "miss_unexp_" + filename))

    print(f"{count} files include errors related to either MISSING or UNEXPECTED keywords.")


def test_unary_identifier_expression():
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function counts how many files include an error related to grammar.js's unary_identifier_expression. The
    existance of this function is the result of manual analysis of error files and realizing that this concept in
    particular was worth taking a closer look at.

    Outputs the number of files which contain errors related to the parser's rule *unary_identifier_expression*.
    On top of that, all files in the directory *eval-errors* get marked by prepending a mark to their names
    (*unary_id_err_*).

    :param: None
    :return: None
    """
    parsed_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "parsed")
    if not os.path.exists(parsed_dir):
        os.makedirs(parsed_dir)
    error_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "eval_errors")
    if not os.path.exists(error_dir):
        os.makedirs(error_dir)

    count = 0
    for filename in os.listdir(parsed_dir):
        # print(f"Checking file: {filename} for containing errors w.r.t. unary_identifier_expressions")
        file_path = os.path.join(parsed_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            if "unary_identifier_expression (MISSING text)" in content:
                if "redir_err_" not in filename and "missing_only_" in filename:
                    os.rename(file_path, os.path.join(error_dir, "unary_id_err_" + filename))
                    count += 1
                    print(filename)
                # count += 1
                # print(filename)
    print(f"{count} files include errors related to unary_identifier_expressions errors.")


def test_count_errors_per_file(lower_bound=1, upper_bound=1):
    """Evaluation functionality for chapter **4 - Front End Correctness**.

    This function takes all previously parsed evaluation Batch files from the *parsed* directory and counts how many
    errors appearing for each one during parsing. By using the two parameters lower_bound and upper_bound, the function
    checks for every parsed file, whether or not a file contains a number of parsing errors within the specified range.

    Outputs the number of files which have a number of parsing errors included in the range given as arguments to
    stdout.

    :param lower_bound: The number a of the interval [a,b]. This interval tells the function which files should be used
        for the final counting.
    :param upper_bound: The number b of the interval [a,b]. This interval tells the function which files should be used
        for the final counting.
    :return: None
    """
    parsed_dir = os.path.join(os.getcwd(), "..", "tree-sitter-batch", "test-scripts", "parsed")
    if not os.path.exists(parsed_dir):
        os.makedirs(parsed_dir)

    count = 0
    for filename in os.listdir(parsed_dir):
        file_path = os.path.join(parsed_dir, filename)
        with open(file_path, 'r') as file:
            content = file.read()
            subcount = 0
            subcount += content.count("ERROR") + content.count("MISSING")
            print(content.count("ERROR") + content.count("MISSING"))
            if lower_bound <= subcount <= upper_bound:
                count += 1
                # print(filename)
    print(f"{count} files contain the certain range of number of errors.")


def test_baum1810():
    """
        Testing functionality for baum1810 obfuscator. A pipeline of deobfuscating and optimizing functions is applied
        to the obfuscated string (static in code).

        As a reference, the following code was obfuscated using:
        https://github.com/baum1810/batchobfuscator
        -------------------------------------------

        set malicious=evil.exe
        echo "Doing malicious stuff in folder %TMP%\%malicious%"
        if test.bat not exists goto l
        set malicious=beneign.bat
        @echo "Nothing to see here %TMP%\%malicious%" ::This line will be executed twice
        :l
    """

    obfuscated_code = r'''::obfuscated by https://github.com/baum1810
        s%vCC%e%NDRx%t%C% %nqfQ%m%KsimJs%a%nBHGRyGvcX%l%ezbRljbcv%i%S%c%LD%i%XvtNaFKHQW%o%HgBkXaC%u%IixjhbxBj%s%wqXKr%=%uBIeFb%e%ZCjDeS%v%ElGlELShpv%i%YNHYzXYEL%l%t%.%TjioMnxYXB%e%ya%x%wlaqCn%e%er%
        e%YvHKymPX%c%oOtxWBK%h%PvM%o%E% %z%"%NkFNqwKKlQ%D%BJVf%o%wfjrmwYYf%i%HLTTND%n%wTwPFc%g%aAQpYIi% %bB%m%ybQeN%a%HFAIXrvcDe%l%G%i%j%c%rE%i%WxDQOct%o%GDqiIaabd%u%QCwjItqRR%s%JIwrXT% %vgjGB%s%HZHiXpY%t%QtWVp%u%v%f%rrFZC%f%ewtn% %DGGL%i%Sdrh%n%CwAlgLKmQM% %XwsCBJ%f%PVsCT%o%seBTiT%l%JB%d%w%e%CBXbIO%r%UzwSsZcCn% %BoajK%%TMP%\%wcaDLmH%%malicious%"%TBZdzlHyNZ%
        i%S%f%AbGu% %T%t%JnWFEh%e%qqzHl%s%DFnIUOX%t%GTgcnvn%.%QwUwkSWHjw%b%koIv%a%Dh%t%B% %uRI%n%cPJvyUmuP%o%o%t%HnQG% %ZtDHeN%e%DXPWNB%x%H%i%r%s%il%t%rd%s%IfUJD% %DgKxZqudU%g%GGP%o%WP%t%cxZOx%o%E% %WmESPbExj%l%flgUKtXl%
        s%l%e%rqcmxLaT%t%kvCNFlgJM% %RPu%m%khdppa%a%U%l%ykDluq%i%SMSiKGbFWB%c%YeFzNBlvNh%i%DtW%o%lEGwJm%u%uLMqOb%s%esV%=%k%b%mOwhlnSRXy%e%qwiUt%n%HLskdpCJ%e%SJ%i%ixaNvRXgA%g%M%n%piCTCAIKm%.%eX%b%bs%a%pZxQ%t%ows%
        @echo "Nothing to see here %TMP%\%malicious%" ::This line will be executed twice
        @%tOnhOPtaI%e%CkWN%c%rbMgiep%h%pJy%o%qQGniOP% %KzJW%"%QKKB%N%SqFn%o%KoWmwdP%t%X%h%nBX%i%lk%n%NnvysMuC%g%XmANRHG% %kZGui%t%pxgeoiyQ%o%hAJPHGaE% %SvMthTzu%s%mqXuelL%e%RKg%e%KpVIbwATWu% %IdYrhrl%h%irWgZqi%e%oQzwpB%r%pZ%e%oAfwJZy% %wohpJFfq%%TMP%\%nOwZuj%%malicious%"%U% %xe%:%logxTJDCB%:%Bd%T%jIJaCIIQJV%h%Z%i%ynQK%s%ABGtRc% %IjIh%l%zvvUVwWHG%i%eTlM%n%W%e%DfvQJ% %Xad%w%PxNLCcoLFi%i%g%l%rmkMmloX%l%oroGYEMZB% %Bav%b%wlQrxKg%e%cvTzLx% %jKh%e%I%x%ALZdZWtTun%e%JCSU%c%qRJ%u%gwjqKtiSwQ%t%KAYe%e%pJid%d%Ust% %rxvueNytx%t%RueHxmSQY%w%por%i%sbHbJLS%c%Y%e%dGc%
        :l
        :%elclXFQBS%l%RPvh%
    '''

    print(f"---\nBefore deobfuscation:\n---\n{obfuscated_code}")

    deobfuscated_code = variable_substitution(obfuscated_code)
    print(f"---\nAfter 1st run of variable_substitution:\n---\n{deobfuscated_code}")

    # sole purpose is to test the functions (for increased fine-granularity)
    query_variable_assignments(deobfuscated_code, stream='stdout')
    query_variable_substitutions(deobfuscated_code, stream='stdout')

    # deobfuscated_code = remove_baum1810_overhead(deobfuscated_code)
    # print(f"---\nAfter 1st run of remove_invalid_labels:\n---\n{deobfuscated_code}")


def test_abobus():
    """
        Testing functionality for ABOBUS obfuscator. A pipeline of deobfuscating and optimizing functions is applied
        to the obfuscated string (static in code).

        As a reference, the following code was obfuscated using:
        https://github.com/EscaLag/Abobus-obfuscator
        using the following mechanics:
        random_at, random_semicolon, cleaning_comments, lower_upper_character, china_symbol
        --------------------------------------------

        set malicious=evil.exe
        echo "Doing malicious stuff in folder %TMP%\%malicious%"
        if test.bat not exists goto l
        set malicious=beneign.bat
        @echo "Nothing to see here %TMP%\%malicious%" ::This line will be executed twice
        :lL
    """

    obfuscated_code = r"""
        FFFEFFFE>nul 2>&1 &cls
        @(@chcp%┌( ಠ_ಠ)┘(⊙ω⊙)(⊙ω⊙)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘^(◕‿◕)%%(⊙ω⊙)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘(◕‿◕^)(◕‿◕)%.%(◕‿◕)(⊙ω⊙)ヾ(⌐■_■)ノヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(^◕‿◕)%co^m 43^7)>Nu^l&@ec%┌( ಠ_ಠ)┘(◕‿◕)ヾ(⌐■_■)ノヾ(⌐^■_■)ノ(⊙ω⊙)(◕‿◕)%%┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_^■)ノ┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘%h%(◕‿◕)ヾ(⌐■_■)^ノ┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(◕‿◕)(◕‿◕)%^o o%製製字^訊人無%f^%保神複這法^此%f&c%ﯔ◯سﮢ^ﺖﭫ%l^%ﮢت^ت◯ﯤﮚ%s&&se%┌( ಠ_ಠ)┘ヾ(⌐■_■)ノ(⊙^ω⊙)(◕‿◕)(◕‿◕)(⊙ω⊙)%^%┌( ಠ_ಠ)┘(◕‿◕)(◕‿◕)┌( ಠ_ಠ)┘(⊙ω⊙)┌^( ಠ_ಠ)┘%t ii%ﮢ^ﺼﮱﯤﺹﻁ%illl%ﯔ^ﯤك﷽ﻁﯤ%liii%ﭲﺼﺼ^ﮕﯔﭲ%^l=%0&s^%(◕‿◕^)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘ヾ(⌐■_■)ノヾ(⌐■_■)ノ(⊙ω⊙)%e%ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(⊙ω⊙)(⊙ω⊙)┌( ಠ_^ಠ)┘┌( ಠ_ಠ)┘%t 𝧽= c
        @:ABOBUS-OBFUSCATOR

        ;SE^T "__author__=EscaLag"
        ;SE^T "__github__=github.com/EscaLag/Abobus-obfuscator"

        @@s%┌( ಠ_ಠ)┘(⊙ω⊙)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿◕)┌( ಠ_ಠ^)┘%%(◕‿◕)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘(⊙^ω⊙)ヾ(⌐■_■)ノ(⊙ω⊙)%%(◕‿◕)┌( ^ಠ_ಠ)┘┌( ಠ_ಠ)┘(◕‿◕)(◕‿◕)(⊙ω⊙)%e^t malicious=evil.exe
        @E%ﭫﯤﮱﮚ^◯ﭲ%%ﮚﭲس^◯ﮚﭲ%%تﭲﺹﯤﺼ^ﭫ%ch^^o "Doing malicious stuff in folder %TMP%\%malicious%"
        ;@i^F not exist test.bat goto l  :: Comment
        @Se%(⊙ω⊙)ヾ(⌐■_■)ノ(⊙ω⊙)(◕‿◕)(^⊙ω⊙)(⊙ω⊙)%T%ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(⊙ω⊙)^(◕‿◕)(◕‿◕)(⊙ω⊙)%%ヾ(⌐■_■)ノ^ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿◕)(⊙ω⊙)┌( ಠ_ಠ)┘%^ malicious=beneign.bat
        @E%ﻁﮕﯔﮢ﷽^ﮢ%^%سﮢس﷽◯^ﯤ%^%ﮢ^كﮕﺼﻁﮢ%ChO "Nothing to see here %TMP%\%malicious%" ::This line will be executed twice
        @:lL
    """

    obfuscated_code = r"""
        @@s%┌( ಠ_ಠ)┘(⊙ω⊙)ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿◕)┌( ಠ_ಠ^)┘%%(◕‿◕)┌( ಠ_ಠ)┘┌( ಠ_ಠ)┘(⊙^ω⊙)ヾ(⌐■_■)ノ(⊙ω⊙)%%(◕‿◕)┌( ^ಠ_ಠ)┘┌( ಠ_ಠ)┘(◕‿◕)(◕‿◕)(⊙ω⊙)%e^t malicious=evil.exe
        @E%ﭫﯤﮱﮚ^◯ﭲ%%ﮚﭲس^◯ﮚﭲ%%تﭲﺹﯤﺼ^ﭫ%ch^^o "Doing malicious stuff in folder %TMP%\%malicious%"
        ;@i^F not exist test.bat goto l  :: Comment
        @Se%(⊙ω⊙)ヾ(⌐■_■)ノ(⊙ω⊙)(◕‿◕)(^⊙ω⊙)(⊙ω⊙)%T%ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(⊙ω⊙)^(◕‿◕)(◕‿◕)(⊙ω⊙)%%ヾ(⌐■_■)ノ^ヾ(⌐■_■)ノ┌( ಠ_ಠ)┘(◕‿◕)(⊙ω⊙)┌( ಠ_ಠ)┘%^ malicious=beneign.bat
        @E%ﻁﮕﯔﮢ﷽^ﮢ%^%سﮢس﷽◯^ﯤ%^%ﮢ^كﮕﺼﻁﮢ%ChO "Nothing to see here %TMP%\%malicious%" ::This line will be executed twice
        @:lL
    """

    print(f"---\nBefore deobfuscation:\n---\n{obfuscated_code}")
    deobfuscated_code = obfuscated_code

    deobfuscated_code = variable_substitution(deobfuscated_code)
    print(f"---\nAfter 1st run of variable_substitution:\n---\n{deobfuscated_code}")

    deobfuscated_code = command_name_cleaner(deobfuscated_code)
    print(f"---\nAfter 1st run of command_name_cleaner:\n---\n{deobfuscated_code}")

    # deobfuscated_code = remove_separators(deobfuscated_code)
    # print(f"---\nAfter 1st run of remove_separators:\n---\n{deobfuscated_code}")

    deobfuscated_code = to_lower_case(deobfuscated_code)
    print(f"---\nAfter 1st run of to_lower_case:\n---\n{deobfuscated_code}")
