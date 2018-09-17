#!/usr/bin/env python
import xml.etree.ElementTree as ET
import re 
try:
    from termcolor import colored
    are_there_colours = True
except:
    are_there_colours = False

#global variables
xml_file_name = 'nvdcve-2.0-recent.xml'
nist_gov_referr = '{http://scap.nist.gov/schema/vulnerability/0.4}'

tolerance_factor = 2 # factor that keeps some margin for validation of version names

vendor1 = 'microsoft'
vend1_prod1 = 'outlook'
vend1_prod2 = 'excel'
vend1_prod3 = 'egde'
vendor2 = 'mozilla'
vend2_prod1 = 'firefox'
vendor3 = 'foxit'
vend3_prod1 = 'reader'
vendor3_1 = 'foxit reader'

#regexp pattern compilations
special_char_pattern = re.compile(r'[\.:-_/\\#,\']')
special_char_pattern_with_s = re.compile(r'[\.:-_/\\#,\s\']')
special_char_pattern_with_rest = re.compile(r'([\.:-_/\\#,\s\'])')

#mock instances
mock_bfi_version_names = { 
'Microsoft Corporation' : {'Internet Explorer' : '11.431.16299.0', 'Vision Vewer' : 'All(Generic Signature)'}, 
'Adobe Systems Incorporated' : {'Acrobat Reader' : '11.0.23.22', 'Macromedia Flash Plyer' : '18.0.0'}, 
'Mozilla Organization' : {'Firefox' : '59.0.2.6656'}, 
'IBM Corporation' : {'Standard Asset Manager' : '7.61.0.0'}
}


#lists
additionals = [
'corporation',
'corp',
'incorporated',
'inc',
'organization',
'org',
'systems',
'developement'
]

'''
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[93m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
'''
   
def log_info(log_string, colour='green'):
    #Function created to keep clear code
    if are_there_colours:
         if colour is 'green':
            print('\033[92m' + '##LOG INFO: ' + str(log_string) + '\033[0m')
         elif colour is 'blue':
            print('\033[94m' + '##LOG INFO: ' + str(log_string) + '\033[0m')
         elif colour is 'yellow':
            print('\033[93m' + '##LOG INFO: ' + str(log_string) + '\033[0m')        
         elif colour is 'red':
            print('\033[91m' + '##LOG INFO: ' + str(log_string) + '\033[0m')
         else:
            print('##LOG INFO: ' + str(log_string))        
    else:  
        print('########### LOG INFO: ' + str(log_string))

def vulner_list_parser(cve_file_name):
    #Function parsing NVD Data Feeds which is XML file published by NVD
    tree = ET.parse(cve_file_name)
    return tree.getroot()

def get_cve_summaries(root):
    cve_summaries = {}
    for child in root:
        id = child.find(nist_gov_referr + 'cve-id').text
        summary = child.find(nist_gov_referr + 'summary').text
        cve_summaries[id] = summary    
    return cve_summaries

def parse_vendor_name(vendor_name):
    #Method deletes unneccessary elements from vendor's name
    new_name_elements = re.split(special_char_pattern, str(vendor_name).lower().strip())
    new_name = ''
    for element in new_name_elements:
        if str(element) not in additionals:
            new_name = new_name + str(element)
    return new_name


def get_rid_of_empty_elements(someList):
    while '' in someList:
        someList.remove('')
    return someList

class SystemProduct(object):
    #Class represents info about specific product from system.
    #Object should be created with info about producent, product and version
    #Object runs self analyse to extract pattern for prod name
    #Later on it holdes info about CVE Entries connected with itself
    def __init__(self, vendor, product_name, ver_name):
        self.venNameStr = parse_vendor_name(vendor)
        self.prodNameStr = product_name
        self.verNameStr = ver_name
        self.lvlLengthList = []
        self.verNameLvlList = re.split(special_char_pattern_with_s, self.verNameStr)
        self.verLvlSpecCharsList = re.split(special_char_pattern_with_rest, self.verNameStr)
        self.regexpLvlPatternList = []  # holds merged patterns created for all levels of version name
        self.verPatternStr = self.ver_pattenr()
        self.cveForProdDict = {}        # all CVE with summaries which mention about give product
        self.cveFindingsDict = {}       # all found CVE with summaries with was matched with pattern
        self.verFindingsDict = {}       # all found matches for pattern {'cve_id' : [match]}
        self.verValidationsDict = {}    # all valid matches ordered {'cve_id':[{'ver_name':levenstein_distance}]}
        self.versionObject = VersionName(self.verNameStr)

        # removing actual names of version levels from special characters list
        for element in self.verNameLvlList:
            self.verLvlSpecCharsList.remove(element)
            self.lvlLengthList.append(len(element))
        
        
    def ver_pattenr(self):
        #Method is dedicated for automatic pattern extraction for product version name 
        VersionObject = VersionName(self.verNameStr)
        VersionObject.create_version_pattern()
        self.regexpLvlPatternList = VersionObject.regexpLvlPatternList
        return VersionObject.regexpString
    
    def look_through_cve_sum(self, xml_cve_summaries):
        #Method looks for CVE Summaries that mention about given product
        vendor = VendorCveAnalizer(self.venNameStr)
        vendor.find_all_vendors_cve(xml_cve_summaries)
        self.cveForProdDict = vendor.find_all_products_cve(self.prodNameStr)
        
    # def look_for_patt_mentions(self):
    #     #Method looks for strings in CVE Summaries matching to the given pattern
    #     compiledPattern  = re.compile(r'' + self.verPatternStr)
    #     for key in self.cveForProdDict:
    #         print(self.cveForProdDict[key] + '\n')
    #         matches = re.findall(compiledPattern, self.cveForProdDict[key])
    #         if matches != []:
    #             self.cveFindingsDict[key] = self.cveForProdDict[key]
    #             self.verFindingsDict[key] = matches
    #         #     log_info('Wiedz, ze cos sie dzieje\n', 'green')
    #         # else:
    #         #     log_info('Wiedz, ze cos sie dzieje\n', 'red')

    def look_for_patt_mentions(self):
        #Method looks for strings in CVE Summaries matching to the given pattern
        for verPatternStr in self.regexpLvlPatternList:
            compiledPattern  = re.compile(r'' + verPatternStr)
            for key in self.cveForProdDict:
                matches = re.findall(compiledPattern, self.cveForProdDict[key])
                if matches != []:
                    try:
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key].append(matches)
                    except KeyError:
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key] = []
                        self.verFindingsDict[key].append(matches)

    def levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[
                                 j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                deletions = current_row[j] + 1  # than s2
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def add_matches(self, lev_dist_of_lvl, ver, key):
        # TODO Decide about acceptable distance to count as match
        if lev_dist_of_lvl <= self.lvlLengthList[-1] + tolerance_factor:
            try:
                self.verValidationsDict[key].append(
                    {str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})
                log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str(
                    {str(ver): lev_dist_of_lvl}), 'yellow')

            except KeyError:
                self.verValidationsDict[key] = []
                self.verValidationsDict[key].append(
                    {str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})
                log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str(
                    {str(ver): lev_dist_of_lvl}), 'yellow')


    def validate_findings(self):
        #Method validates found pattern matches
        for key in self.verFindingsDict:
            log_info('Klucz w self.verFindingsDict: ' + str(key), 'red')
            log_info('Dla przypomnienia zawartosc self.verNameStr: ' + str(self.verNameStr), 'blue')
            log_info('jeszcze jedna wazna sprawa, czyli opis daneo cve: ' + str(self.cveFindingsDict[key]), 'red')

            for ver in self.verFindingsDict[key]:
                ver_iter = 0
                splittedFindingLevels = get_rid_of_empty_elements(re.split(special_char_pattern_with_s, str(ver)))
                splittedProductLevels = get_rid_of_empty_elements(re.split(special_char_pattern_with_s, str(self.verNameStr)))

                log_info('Zawartosc self.verFindingsDict[key]' + str(ver))
                log_info('w tym czasie w splittedFindingLevels: ' + str(splittedFindingLevels), 'yellow')
                log_info('w tym czasie w splittedProductLevels: ' + str(splittedProductLevels), 'yellow')

                # Case when extracted version names are only from the top level
                if len(re.findall(r'' + self.regexpLvlPatternList[0], str(ver))) == len(ver):
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        #Levenstein distance is multiplied by 5 (just high value), because it it the top level of naming
                        # TODO if you revalue other factors you should put here proper value
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[0]) * 5
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        #TODO Decide about acceptable distance to count as match
                        if lev_dist_of_lvl <= self.lvlLengthList[-1] + tolerance_factor:
                            try:
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                                log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(splittedFindingLevels[count]) : lev_dist_of_lvl}), 'blue')
                            except KeyError:
                                self.verValidationsDict[key] = []
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                                log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(splittedFindingLevels[count]) : lev_dist_of_lvl}), 'blue')

                # Case when extracted and expected version name have same count of levels
                # if len(splittedFindingLevels) == len(splittedProductLevels):
                elif len(splittedFindingLevels) == len(splittedProductLevels):
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                    self.add_matches(lev_dist_of_lvl, ver, key)

                # Case when expected version name has more levels than the extracted
                elif len(splittedFindingLevels) < len(splittedProductLevels):
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                    lev_dist_of_lvl = lev_dist_of_lvl + len(splittedProductLevels) - len(splittedFindingLevels)
                    self.add_matches(lev_dist_of_lvl, ver, key)

                # Case when extracted version name has more levels than the expected
                elif len(splittedFindingLevels) > len(splittedProductLevels):
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedProductLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                    self.add_matches(lev_dist_of_lvl, ver, key)

                ver_iter = ver_iter + 1

        log_info('\n\nVALIDATION IS OVER!!\nTheres the results:\n')
        log_info(str(self.verValidationsDict) + '\n', 'red')




class VendorCveAnalizer(object):
    #Class analyses extracted CVE Summaries.
    #Object of class contains all summaries connected with given producent
    def __init__(self, vendor):
        self.venName = parse_vendor_name(vendor)
        self.venSummaries = {}
        
    def find_all_vendors_cve(self, source_dict):
        #Method extracts CVE entries with chosen vendor, based on Summary mention
        for key in source_dict:
            if self.venName.lower().strip() in source_dict[key].lower().strip():
                self.venSummaries[key] = source_dict[key]
        
    def find_all_products_cve(self, product):
        #Method extracts CVE entries with chosen product, based on Summary mention
        product_summ_dict = {}
        for key in self.venSummaries:
            if product.lower().strip() in self.venSummaries[key].lower().strip():
                product_summ_dict[key] = self.venSummaries[key]
        return product_summ_dict
    '''
    def parse_vendor_name(self, vendor_name):
        #Method deletes unneccessary elements from vendor's name
        new_name_elements = re.split(special_char_pattern, str(vendor_name).lower().strip())
        new_name = ''
        for element in new_name_elements:
            if str(element) not in additionals:
                new_name = new_name + str(element)
        log_info('Vendors name: ' + vendor_name + ' was successfully changed to: ' + new_name)
        return new_name        
    '''
    
class LevelName(object):
    def __init__(self, orgStr):
        #Method automatically analyses given string
        #WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        self.originalString = str(orgStr).lower().strip()
        self.length = len(self.originalString)
        self.isThereLetters = re.findall(r'[a-z]+', self.originalString) != []
        self.isThereNumbers = re.findall(r'\d+', self.originalString) != []
        self.regexpString = ''
        self.regexpLvlList = []

    def create_level_pattern(self):
        #Method creates regexp pattern for part of version name
        if self.isThereNumbers and not self.isThereLetters:         # case with level name contains only numbers 
            self.regexpString = '\d{' + str(self.length) + '}'
        elif not self.isThereNumbers and self.isThereLetters:       # case with level name contains only letters
            self.regexpString = '[a-z]{' + str(self.length) + '}'    
        else:                                                       # case with mixed numbers and letters in level name
            # tmpLevelName = re.split(r'([1-9]+)', self.originalString)
            tmpLevelName = get_rid_of_empty_elements(re.split(r'([1-9]+)', self.originalString))
            # if '' in tmpLevelName: tmpLevelName.remove('') #1st element is removed
            # if '' in tmpLevelName: tmpLevelName.remove('') #2nd element is removed
            for element in tmpLevelName:
                level = LevelName(element)
                level.create_level_pattern()
                self.regexpString = self.regexpString + level.regexpString

    
    

class VersionName(object):
    def __init__(self, orgStr):
        #Method automatically analyses given string
        #WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        self.verName = str(orgStr).lower().strip()
        self.length = len(self.verName)
        self.lvlList = re.split(special_char_pattern_with_s, self.verName)
        self.SpecCharList = re.split(special_char_pattern_with_rest, self.verName)
        self.regexpStrList = []             # regexp for each level of version name
        self.regexpString = ''              # whole regexp for given product
        self.regexpLvlPatternList = []      # holds merged patterns created for all levels of version name
        self.lvlLengthList = []
        # removing actual names of version levels from special characters list
        for element in self.lvlList:
            self.SpecCharList.remove(element)
            self.lvlLengthList.append(len(element))

    def check_if_there_is_spec_char(self):
        pass

    def create_version_pattern(self):
        #Method creates pattern based on actual version name existing in the system
        if self.regexpString != '':
            return
        else: 
            for element in self.lvlList:
                level = LevelName(element)
                level.create_level_pattern()
                self.regexpStrList.append(level.regexpString)
            
            #Part of code responsible for creating regexp for version name
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
        #Method created to add escape character for proper special characters
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








    
#script
log_info('Its alive!', 'blue')    

log_info('Extracting XML root\n', 'blue')
xml_cve_root = vulner_list_parser(xml_file_name)

log_info('Creating dictionary with {\'cve-id\' : \'cve-summary\'}\n', 'blue')
xml_cve_summaries = get_cve_summaries(xml_cve_root)    



'''*************LOG INFO ABOUT PATTERN EXTRACTING***************************
log_info('Creating regexp for level name by level_name class', 'red')
level = level_name('234SP34')
level.create_level_pattern()
log_info('level name is equal to: ' + str(level.originalString), 'yellow')
log_info('level name length is equal to: ' + str(level.length), 'yellow')
log_info('level.isThereLetters is equal to: ' + str(level.isThereLetters), 'yellow')
log_info('level.isThereNumbers is equal to: ' + str(level.isThereNumbers), 'yellow')
log_info('level.regexpString is equal to: ' + str(level.regexpString), 'yellow')


log_info('Starting to use regexp in class version_name', 'red')
version = version_name('SP1 234.23.212')
version.create_version_pattern()
log_info('version.versionName is equal to: ' + str(version.versionName), 'yellow')
log_info('version.length is equal to: ' + str(version.length), 'yellow')
log_info('version.listOfLevels is equal to: ' + str(version.listOfLevels), 'yellow')
log_info('version.regexpString is equal to: ' + str(version.regexpString), 'yellow')
'''

'''*************LOG INFO ABOUT SCRIPT CVE EXTRACTING***************************
vendor_filtered_cve_summ = find_all_vendors_cve(xml_cve_summaries, vendor1)
log_info('Findings for ' + vendor1 +' query: ' + str(len(vendor_filtered_cve_summ)))

product_filtered_cve_sum = find_all_products_cve(vendor_filtered_cve_summ, vend1_prod1)
log_info('Findings for ' + vend1_prod1 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n') 

product_filtered_cve_sum = find_all_products_cve(vendor_filtered_cve_summ, vend1_prod2)
log_info('\n\nFindings for ' + vend1_prod2 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')
    
product_filtered_cve_sum = find_all_products_cve(vendor_filtered_cve_summ, vend1_prod3)
log_info('\n\nFindings for ' + vend1_prod3 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')

vendor_filtered_cve_summ = find_all_vendors_cve(xml_cve_summaries, vendor2)
log_info('\n\nFindings for ' + vendor2 +' query: ' + str(len(vendor_filtered_cve_summ)))
    
product_filtered_cve_sum = find_all_products_cve(vendor_filtered_cve_summ, vend2_prod1)
log_info('\n\nFindings for ' + vend2_prod1 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')
'''  

'''*************LOG INFO ABOUT CLASS CVE EXTRACTING***************************

vendor_microsoft = VendorCveAnalizer('microsoft')
vendor_microsoft.find_all_vendors_cve(xml_cve_summaries)
log_info('Findings for ' + vendor_microsoft.vendorName +' query: ' + str(len(vendor_microsoft.vendorSummaries)))

product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod1)
log_info('Findings for ' + vend1_prod1 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n') 

product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod2)
log_info('Findings for ' + vend1_prod2 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')
    
product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod3)
log_info('Findings for ' + vend1_prod3 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')

vendor_mozilla = VendorCveAnalizer('apple')
vendor_mozilla.find_all_vendors_cve(xml_cve_summaries)
log_info('Findings for ' + vendor_mozilla.venName +' query: ' + str(len(vendor_mozilla.venSummaries)))
print(vendor_mozilla.venSummaries)
product_filtered_cve_sum = vendor_mozilla.find_all_products_cve('macos')
log_info('Findings for ' + 'macos' + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')
'''


'''*************LOG INFO ABOUT CVE VALIDATION***************************'''
#SysProd = SystemProduct('Apple', 'macOS', '11.3.5')
SysProd = SystemProduct('Apple', 'macOS', '10.13.5')
SysProd.look_through_cve_sum(xml_cve_summaries)
SysProd.look_for_patt_mentions()
SysProd.validate_findings()
print(SysProd.regexpLvlPatternList)
print('Levenstein at the end is eq to: ', SysProd.levenshtein('abcd', 'abde'))
#print(str(SysProd.verFindingsDict))


'''*************LOG INFO ABOUT LEVENSTEIN VALIDATION***************************
lev = levenshtein('abcde', 'abcde')
log_info('Tak to sobie levek policzyl:  ' + str(lev) + '\n', 'red') #shuld be 0
lev = levenshtein('abcde', 'edcba')
log_info('Tak to sobie levek policzyl:  ' + str(lev)+ '\n', 'red')  #should be 4
lev = levenshtein('abcde', 'ABCDE')
log_info('Tak to sobie levek policzyl:  ' + str(lev)+ '\n', 'red')  #should be 5
'''



oklesttry = {}
oklesttry['ok'] = {'wannabekey' : 'smth'}

print(oklesttry['ok'])
print(oklesttry['ok']['wannabekey'])


#parse_vendor_name('#Microsoft_corporation')