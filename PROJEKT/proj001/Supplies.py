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

#regexp pattern compilations
special_char_pattern = re.compile(r'[\.:-_/\\#,\']')
special_char_pattern_with_s = re.compile(r'[\.:-_/\\#,\s\']')
special_char_pattern_with_rest = re.compile(r'([\.:-_/\\#,\s\'])')


vendor1 = 'microsoft'
vend1_prod1 = 'outlook'
vend1_prod2 = 'excel'
vend1_prod3 = 'egde'
vendor2 = 'mozilla'
vend2_prod1 = 'firefox'
vendor3 = 'foxit'
vend3_prod1 = 'reader'
vendor3_1 = 'foxit reader'


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



def log_info(log_string, colour='green'):
    #Function created to keep clear code
    '''
    HEADER = '\033[95m', OKBLUE = '\033[94m', OKGREEN = '\033[92m', WARNING = '\033[93m',
    FAIL = '\033[91m', ENDC = '\033[0m', BOLD = '\033[1m', UNDERLINE = '\033[4m'
    '''
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