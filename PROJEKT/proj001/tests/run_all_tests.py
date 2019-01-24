from subprocess import call
import os
import Supplies as SUP
import tests.test_Mockingjay as mockingjay
import tests.test_Eragon as eragon
import tests.test_Potter as potter
import tests.test_Metro as metro

# test_path = os.path.dirname(os.path.abspath(__file__))

SUP.tolerance_factor = 2
mockingjay.run_tests()
SUP.tolerance_factor = -1
eragon.run_tests()
SUP.tolerance_factor = -4
potter.run_tests()
SUP.tolerance_factor = -2
metro.run_tests()


print('\n**************************************************************')

print('\nIn Mockingjay test:')
print('Passed:\t', mockingjay.pass_ratio['passed_case'])
print('Failed:\t', mockingjay.pass_ratio['failed_case'])

print('\nIn Eragon test:')
print('Passed:\t', eragon.pass_ratio['passed_case'])
print('Failed:\t', eragon.pass_ratio['failed_case'])

print('\nIn Potter test:')
print('Passed:\t', potter.pass_ratio['passed_case'])
print('Failed:\t', potter.pass_ratio['failed_case'])

print('\nIn Metro test:')
print('Passed:\t', metro.pass_ratio['passed_case'])
print('Failed:\t', metro.pass_ratio['failed_case'])
