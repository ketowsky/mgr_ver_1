import Supplies as SUP
from LevelName import LevelName
import re


class VersionName(object):
    def __init__(self, orgStr):
        # Method automatically analyses given string
        # WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        self.verName = str(orgStr).lower().strip()
        self.length = len(self.verName)
        self.lvlList = re.split(SUP.special_char_pattern_with_s, self.verName)
        self.SpecCharList = re.split(SUP.special_char_pattern_with_rest, self.verName)
        self.regexpStrList = []  # regexp for each level of version name
        self.regexpString = ''  # whole regexp for given product
        self.regexpLvlPatternList = []  # holds merged patterns created for all levels of version name
        self.lvlLengthList = []
        # removing actual names of version levels from special characters list
        for element in self.lvlList:
            self.SpecCharList.remove(element)
            self.lvlLengthList.append(len(element))

    def check_if_there_is_spec_char(self):
        pass

    def create_version_pattern(self):
        # Method creates pattern based on actual version name existing in the system
        if self.regexpString != '':
            return
        else:
            for element in self.lvlList:
                level = LevelName(element)
                level.create_level_pattern()
                self.regexpStrList.append(level.regexpString)

            # Part of code responsible for creating regexp for version name
            self.add_escape_char_for_specials()

            if len(self.regexpStrList) > len(self.SpecCharList):
                for i in range(0, len(self.regexpStrList)):
                    try:
                        self.regexpString = self.regexpString + str(self.regexpStrList[i]) + str(self.SpecCharList[i])
                        self.regexpLvlPatternList.append(self.regexpString)
                    except:
                        self.regexpString = self.regexpString + str(self.regexpStrList[i])
                        self.regexpLvlPatternList.append(self.regexpString)
            else:
                for i in range(0, len(self.SpecCharList)):
                    try:
                        self.regexpString = self.regexpString + str(self.regexpStrList[i]) + str(self.SpecCharList[i])
                        self.regexpLvlPatternList.append(self.regexpString)
                    except:
                        self.regexpString = self.regexpString + str(self.SpecCharList[i])
                        self.regexpLvlPatternList.append(self.regexpString)

    def add_escape_char_for_specials(self):
        # Method created to add escape character for proper special characters
        tmpListOfSpecChar = []
        for element in self.SpecCharList:
            if element == '.':
                tmpListOfSpecChar.append('\.')
            elif element == '\\':
                tmpListOfSpecChar.append('\\')
            elif element == ' ':
                tmpListOfSpecChar.append('\s')
            else:
                tmpListOfSpecChar.append(element)
        self.SpecCharList = tmpListOfSpecChar