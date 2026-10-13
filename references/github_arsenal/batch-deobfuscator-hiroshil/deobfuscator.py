import os
import re
class Deobfuscator():
    def __init__(self):
        self.f = open("test.bat", "r")
        self.data1 = self.f.read()
        self.f.close()
        self.dict1 = self.read_file_to_dict("sample_dict.txt")
        self.keys1 = list(self.dict1.keys())
        self.ffirst = self.data1.find("%")
        self.flast = self.ffirst
    def update_next(self, string, char, ffirst):
        nexts = string.find(char, ffirst + 1)
        if nexts == -1:
            return -1
        return nexts
    def read_file_to_dict(self, filename):
      dict = {}
      with open(filename, "r") as f:
        for line in f:
          words = line.split()[1]
          if words[0] == '"' or words[0] == "'":
            words = words[1:-1]
          words = words.split("=")
          dict[words[0]] = words[1]
      return dict
    def replace_substring(self, string, substring, replacement, index):
      new_string = string[:index] + replacement + string[index + len(substring):]
      return new_string
    def remove_duplicate(self,text,pattern):
        return re.sub(pattern+"+", pattern, text)
    def save(self):
        self.flast = self.update_next(self.data1,"%",self.ffirst)
        c = 0
        while self.ffirst+1 and self.flast+1:
            key1 = self.data1[self.ffirst+1:self.flast]
            isargs = key1.split("\n")[0].strip().isnumeric()
            substring = "%"+key1+"%"
            if key1 in self.keys1:
                val = self.dict1[key1]
                self.data1 = self.replace_substring(self.data1, substring, val, self.ffirst)
                self.ffirst = self.update_next(self.data1,"%",self.flast - (len(substring)-len(val)))
            else:
                exclude = len(substring)
                env = os.environ.get(key1)
                if isargs:
                    self.ffirst = self.flast
                elif not env:
                    self.data1 = self.replace_substring(self.data1, substring, '', self.ffirst)
                    self.ffirst = self.update_next(self.data1,"%",self.flast - exclude)
                else:
                    self.ffirst = self.update_next(self.data1,"%",self.flast)
            self.flast = self.update_next(self.data1,"%",self.ffirst)
        self.data1 = re.sub(' +', ' ',self.data1)
        self.data1 = re.sub(' \n+', '',self.data1)
        print(self.data1)

b1 = Deobfuscator()
b1.save()
