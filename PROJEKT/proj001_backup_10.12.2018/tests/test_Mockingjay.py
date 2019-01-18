#!/usr/bin/env python

import xml.etree.ElementTree as ET
import re

import Supplies as SUP

from SystemProduct import SystemProduct

xml_file_name = 'resources/mock_CVE_list.xml'
xml_cve_root = SUP.vulner_list_parser(xml_file_name)
xml_cve_summaries = SUP.get_cve_summaries(xml_cve_root)
SUP.tolerance_factor = 2

##################################  SETUP  #################################
'''
Producer:           The Hunger Games
Product:            Mockingjay
Wanted Version:     12.345.1410.4
CVE entry source:   resources/mock_CVE_list.xml       

'''
pass_ratio = {'failed_case' : 0, 'passed_case' : 0}
pass_flag = False
# failed_case = 0
# passed_case = 0

SysProd = SystemProduct('The Hunger Games', 'Mockingjay', '12.345.1410.4')
SysProd.look_through_cve_sum(xml_cve_summaries)
SysProd.look_for_patt_mentions()
SysProd.validate_findings()
print(SysProd.regexpLvlPatternList)
print('Levenstein at the end is eq to: ', SysProd.levenshtein('abcd', 'abde'))
print('Version findings:\n' + str(SysProd.verFindingsDict))

for key in SysProd.verValidationsDict:
    print('KEY: ' + str(key))
    print('VALUE: ' + str(SysProd.verValidationsDict[key]))

############################### COMMONS ###############################
def check_if_mentioned(cve_id):
    print("\n\nvvvvvvvvvvvvvvvvvvvvvvvv")
    print('LOOKING FOR: ' + cve_id)
    print('in dictionary: ' + str(SysProd.verValidationsDict))
    if str(cve_id) in SysProd.verValidationsDict:
        print('PASSED')
        return True
        # pass_ratio['passed_case'] = pass_ratio['passed_case'] + 1
    else:
        print('FAILED')
        return False
        # pass_ratio['failed_case'] = pass_ratio['failed_case'] + 1

def check_if_NOT_mentioned(cve_id):
    print("\n\nvvvvvvvvvvvvvvvvvvvvvvvv")
    print('NOT LOOKING FOR: ' + cve_id)
    print('in dictionary: ' + str(SysProd.verValidationsDict))
    if str(cve_id) in SysProd.verValidationsDict:
        print('FAILED')
        return False
        # pass_ratio['passed_case'] = pass_ratio['passed_case'] + 1
    else:
        print('PASSED')
        return True
        # pass_ratio['failed_case'] = pass_ratio['failed_case'] + 1

def evaluate_if_passed(pass_flag):
    if pass_flag:
        pass_ratio['passed_case'] = pass_ratio['passed_case'] + 1
    else:
        pass_ratio['failed_case'] = pass_ratio['failed_case'] + 1

############################### TEST CASE 1  ###############################
'''
CVE: CVE-2009-1111
Producer: The Hunger Games
Product: Mockingjay
Version: from 12.345.1410.4 to 12.345.2137.2
Description: Simple case with mentioned wanted version. 
             Test checks if CVE will be matched.

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2009-1111')
evaluate_if_passed(pass_flag)



############################### TEST CASE 2  ###############################
'''
CVE: CVE-2009-1122
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1410.4, 12.345.1410.5, 12.345.1410.6, 12.345.1408.2, 12.345.1408.4 and 12.345.2137.2
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched. 
             Test checks if other version names will be counted as matches. Differences are at minimum level.

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2009-1122')
evaluate_if_passed(pass_flag)

############################### TEST CASE 3  ###############################
'''
CVE: CVE-2009-1133
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1410.4, 12.345.1409.4, 12.345.2137.4, 12.345.2137.2, 12.478.1410.4 and 15.345.1410.4
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched. 
             Test checks if other version names will be counted as matches. Differences are at medium level.

'''

pass_flag = False
pass_flag = check_if_mentioned('CVE-2009-1133')
evaluate_if_passed(pass_flag)

############################### TEST CASE 4  ###############################
'''
CVE: CVE-2009-1144
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1409.4, 12.345.2137.4, 12.345.2137.2, 12.478.1410.4 and 15.345.1410.4
Description: No matches. Versions at various levels of mention but there is no wanted version.

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2009-1144')
evaluate_if_passed(pass_flag)

############################### TEST CASE 5  ###############################
'''
CVE: CVE-2009-1155
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.2137.2, 12.478.1410.4 and 15.345.1410.4
Description: No matches. Versions at various (but rather high) levels of mention but there is no wanted version.

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2009-1155')
evaluate_if_passed(pass_flag)

############################### TEST CASE 6  ###############################
'''
CVE: CVE-2009-1166
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1410.4
Description: Case with mentioned wanted version. There is only exact version name.

'''

pass_flag = False
pass_flag = check_if_mentioned('CVE-2009-1166')
evaluate_if_passed(pass_flag)


############################### TEST CASE 7  ###############################
'''
CVE: CVE-2009-1177
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.2137.2, 12.345.2137.3, 12.345.2137.4, 12.345.2137.5, 12.345.2169.2, 12.345.2697.2
Description: No matches. Versions different from wanted at medium level.

'''

pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2009-1177')
evaluate_if_passed(pass_flag)


############################### TEST CASE 8  ###############################
'''
CVE: CVE-2009-1188
Producer: The Hunger Games
Product: Mockingjay
Version: 13.345.1410.4, 14.345.1410.4, 15.345.1410.4, 16.345.1410.4, 17.345.1410.4 and 12.345.2137.2
Description: No matches..
             Version names mostly different from wanted at highest level and should not be matched.

'''

pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2009-1188')
evaluate_if_passed(pass_flag)


############################### TEST CASE 9  ###############################
'''
CVE: CVE-2009-1199
Producer: The Hunger Games
Product: Mockingjay
Version: from 14.657.2656.1 to 14.657.2656.9
Description: No matches. There is a range of versions but wanted version is not in the range.

'''

pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2009-1199')
evaluate_if_passed(pass_flag)



############################### TEST CASE 10 ###############################
'''
CVE: CVE-2014-2211
Producer: The Hunger Games Corp.
Product: Mockingjay
Version: 14.345.1410.4 and 14.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing producer names is handling properly additionals in name

'''

pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2014-2211')
evaluate_if_passed(pass_flag)


############################### TEST CASE 11 ###############################
'''
CVE: CVE-2011-3172
Producer: pam_modules
Product: SUSE SUSE
Version: Linux Enterprise
Description: No matches. Completely different product than wanted. 
             Test checks if this CVE entry is not mentioned in any list with matched entries 

'''

pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2011-3172')
evaluate_if_passed(pass_flag)


############################### TEST CASE 12 ###############################
'''
CVE: CVE-2014-2222
Producer: the hunger games
Product: Mockingjay
Version: 12.345.1410.4, 14.400.1000.5 and 15.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing producer names is handling properly small letters in name

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2014-2222')
evaluate_if_passed(pass_flag)

############################### TEST CASE 13 ###############################
'''
CVE: CVE-2014-2233
Producer: The Hunger Games
Product: mockingjay
Version: 12.345.1410.4 and 12.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing product names is handling properly small letters in name

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2014-2233')
evaluate_if_passed(pass_flag)

############################### TEST CASE 14 ###############################
'''
CVE: CVE-2014-2244
Producer: The Hunger Games
Product: Mockingjay
Version: from 14.345.1000.1 to 14.400.1000.5
Description: Case with mentioned wanted version.
             Wanted version is contained in given range.
             WARNING! The feature checking if wanted version is in the range is not implemented yet.
                      Till implementation is ready positive result is negative result.
'''
pass_flag = False
#TODO change when feature for checking in ranges is done
pass_flag = check_if_NOT_mentioned('CVE-2014-2244')
evaluate_if_passed(pass_flag)

############################### TEST CASE 15 ###############################
'''
CVE: CVE-2014-2255
Producer: The Hunger Games
Product: kosoglos
Version: 12.345.1410.4 and 12.400.1000.5
Description: Case with no mentions.
             Test checks if product is filtered properly. Case with wrong product name but with proper version name

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2014-2255')
evaluate_if_passed(pass_flag)

############################### TEST CASE 16 ###############################
'''
CVE: CVE-2014-2266
Producer: The Hunger Games
Product: kosoglos
Version: 12.345.2020.4 and 12.400.1000.5
Description: Case with no mentions.
             Test checks if product is filtered properly. Case with wrong product name and version

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2014-2266')
evaluate_if_passed(pass_flag)

############################### TEST CASE 17 ###############################
'''
CVE: CVE-2014-2277
Producer: Microsoft
Product: Mockingjay
Version: 12.345.1410.4 and 12.400.1000.5
Description: Case with no mentions.
             Test checks if vendor is filtered properly. Case with wrong vendor name but with proper version name

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2014-2277')
evaluate_if_passed(pass_flag)

############################### TEST CASE 18 ###############################
'''
CVE: CVE-2014-2288
Producer: Microsoft
Product: Mockingjay
Version: 12.345.2020.4 and 12.400.1000.5
Description: Case with no mentions.
             Test checks if vendor is filtered properly. Case with wrong vendor name and version name

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2014-2288')
evaluate_if_passed(pass_flag)

print('\nPassed:\t', pass_ratio['passed_case'])
print('\nFailed:\t', pass_ratio['failed_case'])
print("\n\n" + str(SysProd.cveForProdDict.keys()))


print('Levek rzecze, ze ' + str(SysProd.levenshtein('15.345.1410.4', '12.345.1410.4')))