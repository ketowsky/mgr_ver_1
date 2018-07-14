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
special_char_pattern = re.compile(r'[\.:-_/\\#,]')
special_char_pattern_with_s = re.compile(r'[\.:-_/\\#,\s]')
special_char_pattern_with_rest = re.compile(r'([\.:-_/\\#,\s])')

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
    log_info('Vendors name: ' + vendor_name + ' was successfully changed to: ' + new_name)
    return new_name
    
def levenshtein(s1, s2):
    if len(s1) < len(s2):
        return levenshtein(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1 # j+1 instead of j since previous_row and current_row are one character longer
            deletions = current_row[j] + 1       # than s2
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    
    return previous_row[-1]

'''    
def find_all_vendors_cve(source_dict, vendor):
    #Function extracts CVE entries with chosen vendor, based on Summary mention
    log_info('Chosen vendor: ' + vendor)
    new_dict = {}
    for key in source_dict:
        if vendor.lower().strip() in source_dict[key].lower().strip():
            new_dict[key] = source_dict[key]
    return new_dict
    
    
def find_all_products_cve(source_dict, product):
    #Function extracts CVE entries with chosen product, based on Summary mention
    log_info('Chosen product: ' + product)
    new_dict = {}
    for key in source_dict:
        if product.lower().strip() in source_dict[key].lower().strip():
            new_dict[key] = source_dict[key]
    return new_dict

def parse_vendor_name(vendor_name):
    #Function deletes unneccessary elements from vendor's name
    #new_name_elements = re.split(r'[\.:-/\\,_#]', str(vendor_name).lower().strip())
    new_name_elements = re.split(special_char_pattern, str(vendor_name).lower().strip())
    new_name = ''
    for element in new_name_elements:
        if str(element) not in additionals:
            new_name = new_name + str(element)
    log_info('Vendors name: ' + vendor_name + ' was successfully changed to: ' + new_name)
    return new_name
'''
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
            log_info('Len of level: ' + str(len(element)) + ' and element itself: ' + str(element), 'blue')
        
        
    def ver_pattenr(self):
        #Method is dedicated for automatic pattern extraction for product version name 
        VersionObject = VersionName(self.verNameStr)
        VersionObject.create_version_pattern()
        return VersionObject.regexpString
        
    
    def look_through_cve_sum(self, xml_cve_summaries):
        #Method looks for CVE Summaries that mention about given product
        vendor = VendorCveAnalizer(self.venNameStr)
        vendor.find_all_vendors_cve(xml_cve_summaries)
        self.cveForProdDict = vendor.find_all_products_cve(self.prodNameStr)
        log_info('Looking for cve summaries for ' + self.venNameStr + ' ' + self.prodNameStr + ' ver. ' + self.verNameStr, 'red')
        log_info('Findings: ' + str(len(self.cveForProdDict)), 'yellow')
        
    def look_for_patt_mentions(self):
        #Method looks for strings in CVE Summaries matching to the given pattern
        log_info('REGEXP CVE: LOOK AT ME NOW, BITCH: ' + self.verPatternStr + '\n', 'yellow')
        compiledPattern  = re.compile(r'' + self.verPatternStr)
        for key in self.cveForProdDict:
            print(self.cveForProdDict[key] + '\n')
            matches = re.findall(compiledPattern, self.cveForProdDict[key])
            if matches != []:
                self.cveFindingsDict[key] = self.cveForProdDict[key]
                self.verFindingsDict[key] = matches
            #     log_info('Wiedz, ze cos sie dzieje\n', 'green')
            # else:
            #     log_info('Wiedz, ze cos sie dzieje\n', 'red')

    def validate_findings(self):
        #Method validates found pattern matches
        for key in self.verFindingsDict:
            for ver in self.verFindingsDict[key]:
                splittedFindingLevels = re.split(special_char_pattern_with_s, str(ver))
                splittedProductLevels = re.split(special_char_pattern_with_s, str(self.verNameStr))
                if len(splittedFindingLevels) == len(splittedProductLevels):
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        level_factor = levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        log_info('Levenstein distance for level ' + str(count) + ' multiplied by level factor is equal to: ' + str(level_factor), 'yellow')
                    log_info('Levenstein distance for all levels is equal to: ' + str(lev_dist_of_lvl), 'blue')
                    #TODO Decide about acceptable distance to count as match
                    if lev_dist_of_lvl <= self.lvlLengthList[-1]:
                                try:
                                    self.verValidationsDict[key].append({ver: lev_dist_of_lvl})
                                except KeyError:
                                    self.verValidationsDict[key] = []
                                    self.verValidationsDict[key].append({ver: lev_dist_of_lvl})
                                # log_info('Levenstein distance is: ' + str(lev_dist_of_lvl), 'red')
                                # log_info('Found version name is: ' + str(self.verFindingsDict[key]).replace('[', '').replace(']', '').replace('\'', ''), 'red')
                                # log_info('System version name is: ' + self.verNameStr + '\n', 'red')
                else:
                    log_info('Something went wrong with levels name. Check this out in system_product.vlidate_findings()', 'red')
        log_info('!!!Sum of ' + str(len(self.verValidationsDict)) + ' levenstein valid versions was found in this file!!!')
        log_info('ekhm, the validations for findings are like:')
        print(self.verValidationsDict)

    
class VendorCveAnalizer(object):
    #Class analyses extracted CVE Summaries.
    #Object of class contains all summaries connected with given producent
    def __init__(self, vendor):
        self.venName = parse_vendor_name(vendor)
        self.venSummaries = {}
        
    def find_all_vendors_cve(self, source_dict):
        #Method extracts CVE entries with chosen vendor, based on Summary mention
        log_info('Chosen vendor: ' + self.venName)
        for key in source_dict:
            if self.venName.lower().strip() in source_dict[key].lower().strip():
                self.venSummaries[key] = source_dict[key]
        
    def find_all_products_cve(self, product):
        #Method extracts CVE entries with chosen product, based on Summary mention
        log_info('Chosen product: ' + product)
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

    def create_level_pattern(self):
        #Method creates regexp pattern for part of version name
        if self.isThereNumbers and not self.isThereLetters:         # case with level name contains only numbers 
            self.regexpString = '\d{' + str(self.length) + '}'
        elif not self.isThereNumbers and self.isThereLetters:       # case with level name contains only letters
            self.regexpString = '[a-z]{' + str(self.length) + '}'    
        else:                                                       # case with mixed numbers and letters in level name
            tmpLevelName = re.split(r'([1-9]+)', self.originalString)
            if '' in tmpLevelName: tmpLevelName.remove('') #1st element is removed
            if '' in tmpLevelName: tmpLevelName.remove('') #2nd element is removed
            for element in tmpLevelName:
                level = LevelName(element)
                level.create_level_pattern()
                self.regexpString = self.regexpString + level.regexpString
    
    

class VersionName(object):
    def __init__(self, orgStr):
        #Method automatically analyses given string
        #WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        log_info('Creating new instance of version_name class for: ' + str(orgStr))
        self.verName = str(orgStr).lower().strip()
        self.length = len(self.verName)
        self.lvlList = re.split(special_char_pattern_with_s, self.verName)
        self.SpecCharList = re.split(special_char_pattern_with_rest, self.verName)
        self.regexpStrList = []
        self.regexpString = ''
        self.lvlLengthList = []
        # removing actual names of version levels from special characters list
        for element in self.lvlList:
            self.SpecCharList.remove(element)
            self.lvlLengthList.append(len(element))

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
                    except:
                        self.regexpString = self.regexpString + str(self.regexpStrList[i])
            else:
                for i in range(0, len(self.SpecCharList)):
                    try:    
                        self.regexpString = self.regexpString + str(self.regexpStrList[i]) + str(self.SpecCharList[i])
                    except:
                        self.regexpString = self.regexpString + str(self.SpecCharList[i])

     
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
#levDist = levenshtein(str(SysProd.verFindingsDict['CVE-2016-5293']).replace('[', '').replace(']', '').replace('\'', ''), '45.6')
#log_info(str(SysProd.verFindingsDict['CVE-2016-5293']).replace('[', '').replace(']', '').replace('\'', ''), 'yellow')
#log_info(str(levDist))
SysProd.validate_findings()
#print(str(SysProd.verFindingsDict))


'''*************LOG INFO ABOUT LEVENSTEIN VALIDATION***************************
lev = levenshtein('abcde', 'abcde')
log_info('Tak to sobie levek policzyl:  ' + str(lev) + '\n', 'red') #shuld be 0
lev = levenshtein('abcde', 'edcba')
log_info('Tak to sobie levek policzyl:  ' + str(lev)+ '\n', 'red')  #should be 4
lev = levenshtein('abcde', 'ABCDE')
log_info('Tak to sobie levek policzyl:  ' + str(lev)+ '\n', 'red')  #should be 5
'''


#parse_vendor_name('#Microsoft_corporation')