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
Producer:           Gluchovsky
Product:            METRO
Wanted Version:     20.33
CVE entry source:   resources/mock_CVE_list.xml       

'''
pass_ratio = {'failed_case' : 0, 'passed_case' : 0}
pass_flag = False
SUP.tolerance_factor = -2
# failed_case = 0
# passed_case = 0

SysProd = SystemProduct('Gluchovsky', 'METRO', '20.33')
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


def get_rid_of_spec_char_at_the_end( nameStr):
    resultStr = re.sub(r'[\W\s]$', '', nameStr)
    return resultStr



def run_tests():
    ############################### TEST CASE 1  ###############################
    '''
    CVE: CVE-2013-5511
    Producer: Gluchovsky
    Product: METRO
    Version: 20.33, 20.34, 20.35
    Description: Simple case with mention.
                 Test checks if CVE will be matched.

    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2013-5511')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 2  ###############################
    '''
    CVE: CVE-2013-5522
    Producer: Gluchovsky
    Product: METRO
    Version: 22.33, 21.33, 30.33
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_NOT_mentioned('CVE-2013-5522')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 3  ###############################
    '''
    CVE: CVE-2013-5533
    Producer: Gluchovsky
    Product: METRO
    Version: 20.34, 20.35, 20.36
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_NOT_mentioned('CVE-2013-5533')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 4  ###############################
    '''
    CVE: CVE-2013-5544
    Producer: Gluchovsky
    Product: METRO
    Version: 20.33.15
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2013-5544')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 5  ###############################
    '''
    CVE: CVE-2013-5555
    Producer: Gluchovsky
    Product: METRO
    Version: 15.20.33, 20.15.33
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_NOT_mentioned('CVE-2013-5555')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 6  ###############################
    '''
    CVE: CVE-2013-5566
    Producer: Gluchovsky
    Product: METRO
    Version: 20.33-20.35
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2013-5566')
    evaluate_if_passed(pass_flag)

    ############################### TEST CASE 7  ###############################
    '''
    CVE: CVE-2013-5577
    Producer: Gluchovsky
    Product: METRO
    Version: 20.31-20.33
    Description: Simple case with mention.
                 Test checks if CVE will be matched.
    
    '''
    pass_flag = False
    pass_flag = check_if_mentioned('CVE-2013-5577')
    evaluate_if_passed(pass_flag)

    ############################################################################
    ############################### VERIFICATION ###############################
    ############################################################################

    print('\nPassed:\t', pass_ratio['passed_case'])
    print('\nFailed:\t', pass_ratio['failed_case'])

