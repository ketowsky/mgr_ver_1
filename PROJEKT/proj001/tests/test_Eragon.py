#!/usr/bin/env python

import xml.etree.ElementTree as ET
import re

import Supplies as SUP

from SystemProduct import SystemProduct

xml_file_name = 'resources/mock_CVE_list.xml'
xml_cve_root = SUP.vulner_list_parser(xml_file_name)
xml_cve_summaries = SUP.get_cve_summaries(xml_cve_root)


##################################  SETUP  #################################
'''
Producer:           Inheritance Corporation
Product:            Eragon
Wanted Version:     5 SP 3.1
CVE entry source:   resources/mock_CVE_list.xml       

'''
pass_ratio = {'failed_case' : 0, 'passed_case' : 0}
pass_flag = False
SUP.tolerance_factor = 3
# failed_case = 0
# passed_case = 0

SysProd = SystemProduct('Inheritance Corporation', 'Eragon', '5 SP 3.1')
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
    print('\nLOOKING FOR: ' + cve_id)
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
    # print('\nNOT LOOKING FOR: ' + cve_id)
    # print('in dictionary: ' + str(SysProd.verValidationsDict))
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


############################### TEST CASE 7  ###############################
'''
CVE: CVE-2018-3377
Producer: Inheritance Corporation
Product: Eragon
Version: from 4 SP 3.1 to 5 SP 3.1
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched if it is mentioned at the end of range

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2018-3377')
evaluate_if_passed(pass_flag)


############################### TEST CASE 1  ###############################
'''
CVE: CVE-2018-3311
Producer: Inheritance Corporation
Product: Eragon
Version: 4 SP 2, 5 SP 3.1 and 6
Description: Simple case with mention. 
             Test checks if CVE will be matched.

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2018-3311')
evaluate_if_passed(pass_flag)

############################### TEST CASE 1.1  ###############################
'''
CVE: CVE-2018-3312
Producer: Inheritance Corporation
Product: Eragon
Version: 4 SP 3.1, 5 SP 3.1 and 6
Description: Simple case with mention. 
             Test case detects if all listed verions are checked and matched 
             Test checks if CVE will be matched.

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2018-3312')
evaluate_if_passed(pass_flag)
############################### TEST CASE 2  ###############################
'''
CVE: CVE-2018-3322
Producer: Inheritance Corporation
Product: Eragon
Version: 4 SP 5.8, 4 SP 2 and 6
Description: Case with no mentions. 
             Test checks if CVE won't be matched.

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3322')
evaluate_if_passed(pass_flag)


############################### TEST CASE 3  ###############################
'''
CVE: CVE-2018-3333
Producer: Inheritance Corporation
Product: Eragon
Version: 5 SP 3.2, 5 SP 3.3 and 5 SP 3.4
Description: Case with no mentions. 
             Test checks if CVE won't be matched. Names different at the lowest version name level

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3333')
evaluate_if_passed(pass_flag)

############################### TEST CASE 4  ###############################
'''
CVE: CVE-2018-3344
Producer: Inheritance Corporation
Product: Eragon
Version: 5 SP 2.1, 5 SP 4.1 and 5 SP 6.1
Description: Case with no mentions. 
             Test checks if CVE won't be matched. Names different at the medium version name level

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3344')
evaluate_if_passed(pass_flag)

############################### TEST CASE 5  ###############################
'''
CVE: CVE-2018-3355
Producer: Inheritance Corporation
Product: Eragon
Version: 1 SP 3.1, 2 SP 3.1 and 3 SP 3.1
Description: Case with no mentions. 
             Test checks if CVE won't be matched. Names different at the highest version name level

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3355')
evaluate_if_passed(pass_flag)


############################### TEST CASE 6  ###############################
'''
CVE: CVE-2018-3366
Producer: Inheritance Corporation
Product: Eragon
Version: from 5 SP 3.1 to 6 SP 3.1
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched if it is mentioned at start of range

'''
pass_flag = False
pass_flag = check_if_mentioned('CVE-2018-3366')
evaluate_if_passed(pass_flag)


# ############################### TEST CASE 7  ###############################
# '''
# CVE: CVE-2018-3377
# Producer: Inheritance Corporation
# Product: Eragon
# Version: from 4 SP 3.1 to 5 SP 3.1
# Description: Case with mentioned wanted version.
#              Test checks if CVE will be matched if it is mentioned at the end of range
#
# '''
# pass_flag = False
# pass_flag = check_if_mentioned('CVE-2018-3377')
# evaluate_if_passed(pass_flag)
#

############################### TEST CASE 8  ###############################
'''
CVE: CVE-2018-3388
Producer: Inheritance Corporation
Product: Eragon
Version: from 4 SP 3.1 to 6 SP 3.1
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched if it is mentioned in the range.
             WARNING! The feature checking if wanted version is in the range is not implemented yet.
                      Till implementation is ready positive result is negative result.

'''
pass_flag = False
#TODO change when feature for checking in ranges is done
pass_flag = check_if_NOT_mentioned('CVE-2018-3388')
evaluate_if_passed(pass_flag)


############################### TEST CASE 9  ###############################
'''
CVE: CVE-2018-3399
Producer: Inheritance Corporation
Product: Eragon
Version: from 6 SP 3.1 to 8 SP 3.1
Description: Case with no mentions. 
             Test checks if CVE won't be matched since version is out of range.


'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3399')
evaluate_if_passed(pass_flag)


############################### TEST CASE 10 ###############################
'''
CVE: CVE-2018-3300
Producer: Inheritance Corporation
Product: Eragon
Version: 15 SP 3.1, 5 SP 13.1, 5 SP 3.11, 5, 3, 1
Description: Case with no mentions. 
             Test checks if CVE won't be matched while some specific name versions are mentioned.
                todo: Consider if this would be better to split into more test cases 

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3300')
evaluate_if_passed(pass_flag)



print('\nPassed:\t', pass_ratio['passed_case'])
print('\nFailed:\t', pass_ratio['failed_case'])