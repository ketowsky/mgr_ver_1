import Supplies as SUP
from VersionName import VersionName
from VendorCveAnalizer import VendorCveAnalizer
import re

class SystemProduct(object):
    #Class represents info about specific product from system.
    #Object should be created with info about producent, product and version
    #Object runs self analyse to extract pattern for prod name
    #Later on it holdes info about CVE Entries connected with itself
    def __init__(self, vendor, product_name, ver_name):
        self.venNameStr = SUP.parse_vendor_name(vendor)
        self.prodNameStr = product_name
        self.verNameStr = ver_name
        self.lvlLengthList = []
        self.verNameLvlList = re.split(SUP.special_char_pattern_with_s, self.verNameStr)
        self.verLvlSpecCharsList = re.split(SUP.special_char_pattern_with_rest, self.verNameStr)
        self.regexpLvlPatternList = []  # holds merged patterns created for all levels of version name
        self.verPatternStr = self.ver_pattenr()
        self.cveForProdDict = {}        # all CVE with summaries which mention about give product
        self.cveFindingsDict = {}       # all found CVE with summaries with was matched with pattern
        self.verFindingsDict = {}       # all found matches for pattern {'cve_id' : [match]}
        self.verValidationsDict = {}    # all valid matches ordered {'cve_id':[{'ver_name':levenstein_distance}]}
        self.versionObject = VersionName(self.verNameStr)

        # removing actual names of version levels from special characters list
        for element in self.verNameLvlList:
            self.verLvlSpecCharsList.remove(element)
            self.lvlLengthList.append(len(element))


    def ver_pattenr(self):
        #Method is dedicated for automatic pattern extraction for product version name
        VersionObject = VersionName(self.verNameStr)
        VersionObject.create_version_pattern()
        self.regexpLvlPatternList = VersionObject.regexpLvlPatternList
        return VersionObject.regexpString

    def look_through_cve_sum(self, xml_cve_summaries):
        #Method looks for CVE Summaries that mention about given product
        vendor = VendorCveAnalizer(self.venNameStr)
        vendor.find_all_vendors_cve(xml_cve_summaries)
        self.cveForProdDict = vendor.find_all_products_cve(self.prodNameStr)

    # def look_for_patt_mentions(self):
    #     #Method looks for strings in CVE Summaries matching to the given pattern
    #     compiledPattern  = re.compile(r'' + self.verPatternStr)
    #     for key in self.cveForProdDict:
    #         print(self.cveForProdDict[key] + '\n')
    #         matches = re.findall(compiledPattern, self.cveForProdDict[key])
    #         if matches != []:
    #             self.cveFindingsDict[key] = self.cveForProdDict[key]
    #             self.verFindingsDict[key] = matches
    #         #     SUP.log_info('Wiedz, ze cos sie dzieje\n', 'green')
    #         # else:
    #         #     SUP.log_info('Wiedz, ze cos sie dzieje\n', 'red')

    def look_for_patt_mentions(self):
        #Method looks for strings in CVE Summaries matching to the given pattern
        for verPatternStr in self.regexpLvlPatternList:
            compiledPattern  = re.compile(r'' + verPatternStr)
            for key in self.cveForProdDict:
                matches = re.findall(compiledPattern, self.cveForProdDict[key])
                if matches != []:
                    try:
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key].append(matches)
                    except KeyError:
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key] = []
                        self.verFindingsDict[key].append(matches)

    def levenshtein(self, s1, s2):
        if len(s1) < len(s2):
            return self.levenshtein(s2, s1)

        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[
                                 j + 1] + 1  # j+1 instead of j since previous_row and current_row are one character longer
                deletions = current_row[j] + 1  # than s2
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def add_matches(self, lev_dist_of_lvl, ver, key):
        # TODO Decide about acceptable distance to count as match
        print('^^^^^^^ Lets see this factor: ' + str(self.lvlLengthList[-1]))
        print('^^^^ And tolerance factor: ' + str(SUP.tolerance_factor))
        print('^^ And given levenstein distance: ' + str(lev_dist_of_lvl) + '\n')
        if lev_dist_of_lvl <= self.lvlLengthList[-1] + SUP.tolerance_factor:
            try:
                self.verValidationsDict[key].append(
                    {str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})
                print('^ COUNTED:\t' + str(ver) + '\t' + str(key) + '\n\n')
                #SUP.log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(ver): lev_dist_of_lvl}), 'yellow')

            except KeyError:
                self.verValidationsDict[key] = []
                self.verValidationsDict[key].append(
                    {str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})
                print('^ COUNTED\n\n')
                #SUP.log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(ver): lev_dist_of_lvl}), 'yellow')


    def validate_findings(self):
        #Method validates found pattern matches
        print('BIG THING!!!\nVersion Finding Dictionary as it is:\n')
        print(str(self.verFindingsDict))
        for key in self.verFindingsDict:
            SUP.log_info('Klucz w self.verFindingsDict: ' + str(key), 'red')
            SUP.log_info('Dla przypomnienia zawartosc self.verNameStr: ' + str(self.verNameStr), 'blue')
            SUP.log_info('jeszcze jedna wazna sprawa, czyli opis daneo cve: ' + str(self.cveFindingsDict[key]), 'red')

            for ver in self.verFindingsDict[key]:
                # print('&&&&&&& ver item: ' + str(ver))
                ver_iter = 0
                splittedFindingLevels = SUP.get_rid_of_empty_elements(re.split(SUP.special_char_pattern_with_s, str(ver)))
                splittedProductLevels = SUP.get_rid_of_empty_elements(re.split(SUP.special_char_pattern_with_s, str(self.verNameStr)))

                SUP.log_info('Zawartosc self.verFindingsDict[key]' + str(ver))
                SUP.log_info('w tym czasie w splittedFindingLevels: ' + str(splittedFindingLevels), 'yellow')
                SUP.log_info('w tym czasie w splittedProductLevels: ' + str(splittedProductLevels), 'yellow')

                # Case when extracted version names are only from the top level
                if len(re.findall(r'' + self.regexpLvlPatternList[0], str(ver))) == len(ver):
                    print("\nDUPA___1")
                    print("Level version name: \t" + str(ver))
                    print("Findings for " + str(self.regexpLvlPatternList[0]) + ": \n" + str(re.findall(r'' + self.regexpLvlPatternList[0], str(ver))))
                    lev_dist_of_lvl = 0
                    # print('Another version is analized. Aaaaand it is: ' + str(ver))
                    for count in range(len(splittedFindingLevels)):
                        #Levenstein distance is multiplied by 5 (just high value), because it it the top level of naming
                        # TODO if you revalue other factors you should put here proper value
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[0]) * 5 + len(splittedFindingLevels)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        #TODO Decide about acceptable distance to count as match
                        if lev_dist_of_lvl <= self.lvlLengthList[-1] + SUP.tolerance_factor:
                            try:
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                                #SUP.log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(splittedFindingLevels[count]) : lev_dist_of_lvl}), 'blue')
                            except KeyError:
                                self.verValidationsDict[key] = []
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                                #SUP.log_info('wlasnie dodaje cos do verValidaonDict: \nkey: ' + str(key) + '\nappend: ' + str({str(splittedFindingLevels[count]) : lev_dist_of_lvl}), 'blue')
                    print(self.verValidationsDict)
                    # print('Sum of level equals: ' + str(lev_dist_of_lvl))
                # Case when extracted and expected version name have same count of levels
                # if len(splittedFindingLevels) == len(splittedProductLevels):
                elif len(splittedFindingLevels) == len(splittedProductLevels):
                    print("DUPA___2\n")
                    lev_dist_of_lvl = 0
                    # print('Another version is analized. Aaaaand it is: ' + str(ver))
                    for count in range(len(splittedFindingLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        # SUP.log_info('Level Distance:\t' + str(lev_dist_of_lvl), 'yellow')
                        # SUP.log_info('Level Factor\t:' + str(level_factor), 'red')
                    self.add_matches(lev_dist_of_lvl, ver, key)
                    # print('Sum of level equals: ' + str(lev_dist_of_lvl))

                # Case when expected version name has more levels than the extracted
                elif len(splittedFindingLevels) < len(splittedProductLevels):
                    print("DUPA___3\n")
                    lev_dist_of_lvl = 0
                    # print('Another version is analized. Aaaaand it is: ' + str(ver))
                    for count in range(len(splittedFindingLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                    lev_dist_of_lvl = lev_dist_of_lvl + len(splittedProductLevels) - len(splittedFindingLevels)
                    self.add_matches(lev_dist_of_lvl, ver, key)
                    # print('Sum of level equals: ' + str(lev_dist_of_lvl))

                # Case when extracted version name has more levels than the expected
                elif len(splittedFindingLevels) > len(splittedProductLevels):
                    print("DUPA___4\n")
                    # print('Another version is analized. Aaaaand it is: ' + str(ver))
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedProductLevels)):
                        level_factor = self.levenshtein(splittedFindingLevels[count], splittedProductLevels[count]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                    self.add_matches(lev_dist_of_lvl, ver, key)
                    # print('Sum of level equals: ' + str(lev_dist_of_lvl))

                else:
                    print("DON DUPA DUPEONE")


                ver_iter = ver_iter + 1



        #SUP.log_info('\n\nVALIDATION IS OVER!!\nTheres the results:\n')
        #SUP.log_info(str(self.verValidationsDict) + '\n', 'red')
