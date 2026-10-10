# You can add your variables. They look like null strings so the script will pass them if they don't state here
sys_variables = ['%TEMP%']


class Deobfuscator:
    def __init__(self, filename: str, with_save: bool = True, save_sets: bool = False):
        self.file = open(filename)
        self.deob_file = open(filename + '.deob', 'w')
        self.obf_strings = {var: var for var in sys_variables}
        self.with_save = with_save
        self.save_sets = save_sets

        self._local = False
        self._use_excl = False
        self._local_variables = {}

    def parse_file(self):
        line = self.file.readline()
        while line:
            string = self.parse_line(self.deobfuscate_line(line))
            if string.lower().startswith(('set', '@set')) and not string.lower().startswith('setlocal'):
                if self.save_sets:
                    print(string, end='')

                    if self.with_save:
                        self.deob_file.write(string)

            elif not string.isspace():
                print(string, end='')
                if self.with_save:
                    self.deob_file.write(string)

            line = self.file.readline()

    def deobfuscate_line(self, line):
        var_storage = self._local_variables if self._local else self.obf_strings
        deobfuscated_string = ''
        key_name = False
        key_name_string = ''
        for symbol in line:

            if symbol in '!%':

                # here local variables state as they are
                if symbol == '!' and not self._local and not self._use_excl:
                    continue

                key_name = not key_name
                if key_name:
                    key_name_string = ''
                else:

                    # string manipulations
                    if ':' in key_name_string:
                        key, condition = key_name_string.split(':')
                        key = var_storage.get(key, None)
                        if key is None:  # just if it is a null string or a bug
                            return ''

                        # pattern replacement
                        if '=' in condition:
                            pattern, replacement = condition.split('=')
                            key = key.replace(pattern, '')
                            deobfuscated_string += key
                            continue

                        # pulling out symbols
                        elif '~' in condition:
                            offset, steps = map(int, condition[1:].split(','))
                            deobfuscated_string += key[offset:offset + steps]
                            continue

                        else:
                            # null string
                            continue

                    if key_name_string == 'systemdrive':
                        deobfuscated_string += '%systemdrive%'
                        continue

                    value = var_storage.get(key_name_string, None)
                    if value is not None:
                        deobfuscated_string += value
                    # else it is a null string
                continue

            if key_name:
                if key_name_string == '' and symbol == '~':
                    key_name = not key_name
                    deobfuscated_string += '%~'
                    continue
                key_name_string += symbol
            else:
                deobfuscated_string += symbol

        return deobfuscated_string

    def parse_line(self, line: str):
        if line.lower().startswith('setlocal'):
            self._local = True
            self._local_variables = self.obf_strings.copy()
            argument = line.lower().split(' ', 1)[1]
            if argument == 'enabledelayedexpansion':
                self._use_excl = True
            if argument == 'disabledelayedexpansion':
                self._use_excl = False
        elif line.lower().startswith('endlocal'):
            self._local = False
            self._local_variables.clear()

        elif line.lower().startswith(('@set', 'set')):
            temp_line = line.split(' ', 1)[1]
            if '"' in line:
                temp_line = temp_line[1:-2]
            key, value = temp_line.split('=', 1)

            self.obf_strings[key] = value

        return line


Deobfuscator("test.txt").parse_file()
