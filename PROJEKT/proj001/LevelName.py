import Supplies as SUP
import re

class LevelName(object):
    def __init__(self, orgStr):
        # Method automatically analyses given string
        # WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        self.originalString = str(orgStr).lower().strip()
        self.length = len(self.originalString)
        self.isThereLetters = re.findall(r'[a-z]+', self.originalString) != []
        self.isThereNumbers = re.findall(r'\d+', self.originalString) != []
        self.regexpString = ''
        self.regexpLvlList = []

    def create_level_pattern(self):
        # Method creates regexp pattern for part of version name
        if self.isThereNumbers and not self.isThereLetters:  # case with level name contains only numbers
            self.regexpString = '\d{' + str(self.length) + '}'
        elif not self.isThereNumbers and self.isThereLetters:  # case with level name contains only letters
            self.regexpString = '[a-z]{' + str(self.length) + '}'
        else:  # case with mixed numbers and letters in level name
            # tmpLevelName = re.split(r'([1-9]+)', self.originalString)
            tmpLevelName = SUP.get_rid_of_empty_elements(re.split(r'([1-9]+)', self.originalString))
            # if '' in tmpLevelName: tmpLevelName.remove('') #1st element is removed
            # if '' in tmpLevelName: tmpLevelName.remove('') #2nd element is removed
            for element in tmpLevelName:
                level = LevelName(element)
                level.create_level_pattern()
                self.regexpString = self.regexpString + level.regexpString
