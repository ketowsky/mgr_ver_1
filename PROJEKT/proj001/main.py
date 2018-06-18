#!/usr/bin/env python
import xml.etree.ElementTree as ET
from termcolor import colored
import re 


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
        
#def log_info(log_string, colour='green'):
#    #Function created to keep clear code
#    print('########### LOG INFO: ' + str(log_string))

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

class vendor_cve_analizer():
    def __init__(self, vendor):
        self.vendorName = self.parse_vendor_name(vendor)
        self.vendorSummaries = {}
        
   
    def find_all_vendors_cve(self, source_dict):
        #Method extracts CVE entries with chosen vendor, based on Summary mention
        log_info('Chosen vendor: ' + self.vendorName)
        for key in source_dict:
            if self.vendorName.lower().strip() in source_dict[key].lower().strip():
                self.vendorSummaries[key] = source_dict[key]
        
    def find_all_products_cve(self, product):
        #Method extracts CVE entries with chosen product, based on Summary mention
        log_info('Chosen product: ' + product)
        product_summ_dict = {}
        for key in self.vendorSummaries:
            if product.lower().strip() in self.vendorSummaries[key].lower().strip():
                product_summ_dict[key] = self.vendorSummaries[key]
        return product_summ_dict

    def parse_vendor_name(self, vendor_name):
        #Method deletes unneccessary elements from vendor's name
        #new_name_elements = re.split(r'[\.:-/\\,_#]', str(vendor_name).lower().strip())
        new_name_elements = re.split(special_char_pattern, str(vendor_name).lower().strip())
        new_name = ''
        for element in new_name_elements:
            if str(element) not in additionals:
                new_name = new_name + str(element)
        log_info('Vendors name: ' + vendor_name + ' was successfully changed to: ' + new_name)
        return new_name        

class level_name(object):  
    def __init__(self, orgStr):
        #Method automatically analyses given string
        #WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        log_info('Creating new instance of level_name class for: ' + str(orgStr))
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
                level = level_name(element)
                level.create_level_pattern()
                self.regexpString = self.regexpString + level.regexpString
    
    

class version_name(object):
    def __init__(self, orgStr):
        #Method automatically analyses given string
        #WARNING: There is some simplification - it has been assumpted that in version name
        #         it is not important if there is lower or upper case
        log_info('Creating new instance of version_name class for: ' + str(orgStr))
        self.versionName = str(orgStr).lower().strip()
        self.length = len(self.versionName)
        self.listOfLevels = re.split(special_char_pattern_with_s, self.versionName)
        self.listOfSpecChar = re.split(special_char_pattern_with_rest, self.versionName)
        self.listOfRegexpStrings = []
        self.regexpString = ''
        # removing actual names of version levels from specil characters list
        for element in self.listOfLevels:
            self.listOfSpecChar.remove(element)
        
    def create_version_pattern(self):
        #Method creates pattern based on actual version name existing in the system
        for element in self.listOfLevels:
            level = level_name(element)
            level.create_level_pattern()
            self.listOfRegexpStrings.append(level.regexpString)
        
        #Part of code responsible for creating regexp for version name
        self.regexpString = 'r\''
        self.add_escape_char_for_specials()

        if len(self.listOfRegexpStrings) > len(self.listOfSpecChar):
            for i in range(0, len(self.listOfRegexpStrings)):
                try:    
                    self.regexpString = self.regexpString + str(self.listOfRegexpStrings[i]) + str(self.listOfSpecChar[i])
                except:
                    self.regexpString = self.regexpString + str(self.listOfRegexpStrings[i])
        else:
            for i in range(0, len(self.listOfSpecChar)):
                try:    
                    self.regexpString = self.regexpString + str(self.listOfRegexpStrings[i]) + str(self.listOfSpecChar[i])
                except:
                    self.regexpString = self.regexpString + str(self.listOfSpecChar[i])     

        self.regexpString = self.regexpString + '\''
     
    def add_escape_char_for_specials(self):
        #Method created to add escape character for proper special characters
        tmpListOfSpecChar = []
        for element in self.listOfSpecChar:
            if element == '.':
                tmpListOfSpecChar.append('\.')
            elif element == '\\':
                tmpListOfSpecChar.append('\\')
            elif element == ' ':
                tmpListOfSpecChar.append('\s')
            else:
                tmpListOfSpecChar.append(element)
        self.listOfSpecChar = tmpListOfSpecChar











    
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

'''*************LOG INFO ABOUT CVE EXTRACTING***************************
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

'''*************LOG INFO ABOUT CLASS CVE EXTRACTING***************************'''

vendor_microsoft = vendor_cve_analizer('microsoft')
vendor_microsoft.find_all_vendors_cve(xml_cve_summaries)
log_info('Findings for ' + vendor_microsoft.vendorName +' query: ' + str(len(vendor_microsoft.vendorSummaries)))

product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod1)
log_info('Findings for ' + vend1_prod1 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n') 

product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod2)
log_info('\n\nFindings for ' + vend1_prod2 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')
    
product_filtered_cve_sum = vendor_microsoft.find_all_products_cve(vend1_prod3)
log_info('\n\nFindings for ' + vend1_prod3 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')

vendor_mozilla = vendor_cve_analizer('mozilla')
vendor_mozilla.find_all_vendors_cve(xml_cve_summaries)
log_info('Findings for ' + vendor_mozilla.vendorName +' query: ' + str(len(vendor_mozilla.vendorSummaries)))
    
product_filtered_cve_sum = vendor_mozilla.find_all_products_cve(vend2_prod1)
log_info('\n\nFindings for ' + vend2_prod1 + ' query: ' + str(len(product_filtered_cve_sum)))
log_info('Printing for Product Dictionary')    
for key in product_filtered_cve_sum:
    print(key, ':', product_filtered_cve_sum[key], '\n')



#parse_vendor_name('#Microsoft_corporation')