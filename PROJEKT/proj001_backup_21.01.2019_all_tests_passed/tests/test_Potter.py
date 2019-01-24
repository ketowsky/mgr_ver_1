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
Producer:           Harry
Product:            Potter
Wanted Version:     2010
CVE entry source:   resources/mock_CVE_list.xml       

'''
pass_ratio = {'failed_case' : 0, 'passed_case' : 0}
pass_flag = False
SUP.tolerance_factor = -4
# failed_case = 0
# passed_case = 0

SysProd = SystemProduct('Harry', 'Potter', '2010')
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
    if str(cve_id) in SysProd.verValidationsDict:
        print('PASSED')
        print('in dictionary ' + str(cve_id) + ': ' + str(SysProd.verValidationsDict[cve_id]))
        return True
    else:
        print('FAILED')
        print('in dictionary: ' + str(SysProd.verValidationsDict))
        return False

def check_if_NOT_mentioned(cve_id):
    print('\nNOT LOOKING FOR: ' + cve_id)
    if str(cve_id) in SysProd.verValidationsDict:
        print('FAILED')
        print('in dictionary ' + str(cve_id) + ': ' + str(SysProd.verValidationsDict[cve_id]))
        return False
    else:
        print('PASSED')
        print('in dictionary: ' + str(SysProd.verValidationsDict))
        return True

def evaluate_if_passed(pass_flag):
    if pass_flag:
        pass_ratio['passed_case'] = pass_ratio['passed_case'] + 1
    else:
        pass_ratio['failed_case'] = pass_ratio['failed_case'] + 1

def run_tests():
    ############################### TEST CASE 1  ###############################
    '''
    CVE: CVE-2010-4411
    Producer: Harry Corp.
    Product: Potter
    Version: 2008, 2010, 2012
    Description: Simple case with mention.
                 Test checks if CVE will be matched.

    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2010-4411')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 2  ###############################
    '''
    CVE: CVE-2010-4422
    Producer: Harry Corp.
    Product: Potter
    Version: 2007, 2009, 2011
    Description: Simple case with no mentions. 
                 Test checks if CVE won't be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_NOT_mentioned('CVE-2010-4422')
    evaluate_if_passed(pass_flag)


    ############################### TEST CASE 3  ###############################
    '''
    CVE: CVE-2010-4433
    Producer: Harry Corp.
    Product: Potter
    Version: 2010-2016
    Description: Case with mentions. 
                 Test checks opening boundary conditions. 
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2010-4433')
    evaluate_if_passed(pass_flag)


    ############################### TEST CASE 4  ###############################
    '''
    CVE: CVE-2010-4444
    Producer: Harry Corp.
    Product: Potter
    Version: 2005-2010
    Description: Case with mentions. 
                 Test checks closing boundary conditions.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2010-4444')
    evaluate_if_passed(pass_flag)


    ############################### TEST CASE 5  ###############################
    '''
    CVE: CVE-2010-4455
    Producer: Harry Corp.
    Product: Potter
    Version: 201, 210, 2101, 2110
    Description: No mentions.
                 Version names are similar to looked for 
                 Test checks if CVE won't be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_NOT_mentioned('CVE-2010-4455')
    evaluate_if_passed(pass_flag)


    ############################### TEST CASE 6  ###############################
    '''
    CVE: CVE-2010-4466
    Producer: Harry Corp.
    Product: Potter
    Version: 2010 SP 1
    Description: Case with mention.
                 Version name is extended but should be counted as match 
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2010-4466')
    evaluate_if_passed(pass_flag)


    ############################################################################
    ############################### VERIFICATION ###############################
    ############################################################################

    print('\nPassed:\t', pass_ratio['passed_case'])
    print('\nFailed:\t', pass_ratio['failed_case'])