#!/usr/bin/env python

import xml.etree.ElementTree as ET
import re

import Supplies as SUP

from SystemProduct import SystemProduct

xml_file_name = 'resources/tmp_CVE_file.xml'
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
CVE: CVE-2018-3377
Producer: Inheritance Corporation
Product: Eragon
Version: from 4 SP 3.1 to 5 SP 3.1
Description: Case with mentioned wanted version. 
             Test checks if CVE will be matched if it is mentioned at the end of range

'''
pass_flag = False
pass_flag = check_if_NOT_mentioned('CVE-2018-3300')
evaluate_if_passed(pass_flag)



# ############################### TEST CASE 2  ###############################
# '''
# CVE: CVE-2018-3366
# Producer: Inheritance Corporation
# Product: Eragon
# Version: from 5 SP 3.1 to 6 SP 3.1
# Description: Case with mentioned wanted version.
#              Test checks if CVE will be matched if it is mentioned at start of range
#
# '''
# pass_flag = False
# pass_flag = check_if_mentioned('CVE-2018-3366')
# evaluate_if_passed(pass_flag)





print('\nPassed:\t', pass_ratio['passed_case'])
print('\nFailed:\t', pass_ratio['failed_case'])