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
Producer:           The Hunger Games
Product:            Mockingjay
Wanted Version:     12.345.1410.4
CVE entry source:   resources/mock_CVE_list.xml       

'''


SysProd = SystemProduct('The Hunger Games', 'Mockingjay', '12.345.1410.4')
SysProd.look_through_cve_sum(xml_cve_summaries)
SysProd.look_for_patt_mentions()
SysProd.validate_findings()
print(SysProd.regexpLvlPatternList)
print('Levenstein at the end is eq to: ', SysProd.levenshtein('abcd', 'abde'))


############################### TEST CASE 1  ###############################
'''
CVE: CVE-2009-1111
Producer: The Hunger Games
Product: Mockingjay
Version: from 12.345.1410.4 to 12.345.2137.2
Description: Simple case with mentioned wanted version. 
             Test checks if CVE will be matched.

'''


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

############################### TEST CASE 4  ###############################
'''
CVE: CVE-2009-1144
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1409.4, 12.345.2137.4, 12.345.2137.2, 12.478.1410.4 and 15.345.1410.4
Description: No matches. Versions at various levels of mention but there is no wanted version.

'''

############################### TEST CASE 5  ###############################
'''
CVE: CVE-2009-1155
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.2137.2, 12.478.1410.4 and 15.345.1410.4
Description: No matches. Versions at various (but rather high) levels of mention but there is no wanted version.

'''

############################### TEST CASE 6  ###############################
'''
CVE: CVE-2009-1166
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.1410.4
Description: Case with mentioned wanted version. There is only exact version name.

'''

############################### TEST CASE 7  ###############################
'''
CVE: CVE-2009-1177
Producer: The Hunger Games
Product: Mockingjay
Version: 12.345.2137.2, 12.345.2137.3, 12.345.2137.4, 12.345.2137.5, 12.345.2169.2, 12.345.2697.2
Description: No matches. Versions different from wanted at medium level.

'''

############################### TEST CASE 8  ###############################
'''
CVE: CVE-2009-1188
Producer: The Hunger Games
Product: Mockingjay
Version: 13.345.1410.4, 14.345.1410.4, 15.345.1410.4, 16.345.1410.4, 17.345.1410.4 and 12.345.2137.2
Description: Case with mentioned wanted version.
             Other version names different from wanted at highest level and should not be matched.

'''

############################### TEST CASE 9  ###############################
'''
CVE: CVE-2009-1199
Producer: The Hunger Games
Product: Mockingjay
Version: from 14.657.2656.1 to 14.657.2656.9
Description: No matches. There is a range of versions but wanted version is not in the range.

'''

############################### TEST CASE 10 ###############################
'''
CVE: 2211
Producer: The Hunger Games
Product: Mockingjay
Version: from 14.345.1000.1 to 14.400.1000.5
Description: Case with mentioned wanted version.
             Wanted version is contained in given range.
             WARNING! The feature checking if wanted version is in the range is not implemented yet.
                      Till implementation is ready positive result is negative result.

'''

############################### TEST CASE 11 ###############################
'''
CVE: CVE-2011-3172
Producer: pam_modules
Product: SUSE SUSE
Version: Linux Enterprise
Description: No matches. Completely different product than wanted. 
             Test checks if this CVE entry is not mentioned in any list with matched entries 

'''

############################### TEST CASE 12 ###############################
'''
CVE: CVE-2014-2222
Producer: the hunger games
Product: Mockingjay
Version: 14.345.1410.4, 14.400.1000.5 and 15.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing producer names is handling properly small letters in name

'''

############################### TEST CASE 13 ###############################
'''
CVE: CVE-2014-2233
Producer: The Hunger Games
Product: mockingjay
Version: 14.345.1410.4 and 14.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing product names is handling properly small letters in name

'''


############################### TEST CASE 14 ###############################
'''
CVE: CVE-2014-2244
Producer: The Hunger Games Corp.
Product: Mockingjay
Version: 14.345.1410.4 and 14.400.1000.5
Description: Case with mentioned wanted version.
             Test checks if feature parsing producer names is handling properly additionals in name

'''
