#!/usr/bin/env python

import xml.etree.ElementTree as ET
import re 

import Supplies as SUP

from SystemProduct import SystemProduct

    
#script
SUP.log_info('Its alive!', 'blue')

SUP.log_info('Extracting XML root\n', 'blue')
xml_cve_root = SUP.vulner_list_parser(SUP.xml_file_name)

SUP.log_info('Creating dictionary with {\'cve-id\' : \'cve-summary\'}\n', 'blue')
xml_cve_summaries = SUP.get_cve_summaries(xml_cve_root)



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