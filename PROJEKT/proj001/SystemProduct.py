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
        self.verNameStr = ver_name.lower()
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

    def get_rid_of_spec_char_at_the_end(self, nameStr):
        print('\n+++++++++++ nameStr\n' + nameStr)
        resultStr = re.sub(r'[\W\s]$', '', nameStr)
        print('\n+++++++++++ resultStr\n' + resultStr)
        return resultStr.strip()

    def ver_pattenr(self):
        #Method is dedicated for automatic pattern extraction for product version name
        VersionObject = VersionName(self.verNameStr)
        VersionObject.create_version_pattern()
        self.regexpLvlPatternList = VersionObject.regexpLvlPatternList
        return VersionObject.regexpString

    def look_through_cve_sum(self, xml_cve_summaries):
        #Method looks for CVE Summaries that mention about given product
        vendor = VendorCveAnalizer(self.venNameStr)
        ##### This part is dedicated for case where match should be found at the end of range constructed like 230-234
        tmp_var = self.verNameStr.split('-')
        if len(tmp_var) == 1:
            for key in xml_cve_summaries:
                xml_cve_summaries[key] = str(xml_cve_summaries[key]).replace('-', '  ')
        #####
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
        # print("+-+-+-+-+-+-+-+-+-+-+-+-+\n")
        # print(str(self.regexpLvlPatternList))
        # print("\n-+-+-+-+-+-+-+-+-+-+-+-+-")
        for verPatternStr in self.regexpLvlPatternList:
            # compiledPattern = re.compile(r'' + verPatternStr + '\\W')
            ### matches cases with space before pattern, it's helping with given 15.02 in case of looking for 5.02
            # compiledPattern = re.compile(r'\s' + verPatternStr + '\\W')
            ### solves problem the solution above, which is case with range for example: 3.05-5.02
            compiledPattern  = re.compile(r'\W' + verPatternStr + '\\W')
            print("\ncomplied pattern:")
            print(str(compiledPattern))
            for key in self.cveForProdDict:
                # print("key in cveForProdDict: " + str(key))
                # print("and cveForProdDict itself: " + str(self.cveForProdDict))
                matches = re.findall(compiledPattern, self.cveForProdDict[key])
                if matches != []:
                    try:
                        tmp_matches = []
                        for item in matches:
                            tmp_matches.append(self.get_rid_of_spec_char_at_the_end(item))
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key].append(tmp_matches)
                        print("@@@@@@@@@@@@@@@@@ matches: " + str(matches))
                        print("@@@@@@@@@@@@@@@@@ tmp_matches: " + str(tmp_matches))
                    except KeyError:
                        tmp_matches = []
                        for item in matches:
                            tmp_matches.append(self.get_rid_of_spec_char_at_the_end(item))
                        self.cveFindingsDict[key] = self.cveForProdDict[key]
                        self.verFindingsDict[key] = []
                        self.verFindingsDict[key].append(tmp_matches)
                        print("@@@@@@@@@@@@@@@@@ matches: " + str(matches))
                        print("@@@@@@@@@@@@@@@@@ tmp_matches: " + str(tmp_matches))
                # if matches != []:
                #     try:
                #         tmp_matches = []
                #         for item in matches:
                #             tmp_matches.append(item.replace(' ', '').replace('-', '').replace(',', ''))
                #         self.cveFindingsDict[key] = self.cveForProdDict[key]
                #         self.verFindingsDict[key].append(tmp_matches)
                #         print("@@@@@@@@@@@@@@@@@ matches: " + str(tmp_matches))
                #     except KeyError:
                #         tmp_matches = []
                #         for item in matches:
                #             tmp_matches.append(item.replace(' ', '').replace('-', '').replace(',', ''))
                #         self.cveFindingsDict[key] = self.cveForProdDict[key]
                #         self.verFindingsDict[key] = []
                #         self.verFindingsDict[key].append(tmp_matches)
                #         print("@@@@@@@@@@@@@@@@@ matches: " + str(tmp_matches))

    def evaluate_edit_distance(self, s1, s2, metric='levenshtein'):
         ###              Default metric of edit distance is Levenshtein
         ###   Levenshtein
         print('\n\n' + '@@@@@' +'\n\n' + str(metric) + '\n\n' + '@@@@@' +'\n\n')
         if metric == 'levenshtein':
            if len(s1) < len(s2):
                return self.evaluate_edit_distance(s2, s1)

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
         else:
             print('\nERROR:\tMetric: \'' + str(metric) + '\' is not valid\n')

    def add_matches(self, lev_dist_of_lvl, ver, key):
        # TODO #1 it is possible that not whole 'ver' should be used as 'key' in verValidationsDict
        # TODO #2 Decide about acceptable distance to count as match
        if lev_dist_of_lvl <= self.lvlLengthList[-1] + SUP.tolerance_factor:
            try:
                self.verValidationsDict[key].append({str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})

            except KeyError:
                self.verValidationsDict[key] = []
                self.verValidationsDict[key].append({str(ver).replace('[', '').replace(']', '').replace('\'', ''): lev_dist_of_lvl})
        print("\n\nWololololololololo\n" + str(self.verValidationsDict) + "\n\n")

    def validate_findings(self):
        #Method validates found pattern matches
        print('BIG THING!!!\nVersion Finding Dictionary as it is:\n')
        print(str(self.verFindingsDict))
        for key in self.verFindingsDict:

            for ver in self.verFindingsDict[key]:

                ver_iter = 0
                splittedFindingLevels = SUP.get_rid_of_empty_elements(re.split(SUP.special_char_pattern_with_s, str(ver)))
                splittedProductLevels = SUP.get_rid_of_empty_elements(re.split(SUP.special_char_pattern_with_s, str(self.verNameStr)))

                tmp_flag = False

                rexp_tmp = re.findall(r'' + self.regexpLvlPatternList[0], str(ver))
                for iter in range(0,len(ver)):
                    if len(ver[iter]) == len(rexp_tmp[iter]):
                        print(str(ver[iter])+ ' ' + str(rexp_tmp[iter]))
                        tmp_flag = True

                # Case when extracted version names are only from the top level
                if tmp_flag:
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        lev_dist_of_lvl = 0
                        print("\n>>>>>>>>>>  validation in progress: im in dupa1\n")
                        #Levenstein distance is multiplied by 5 (just high value), because it it the top level of naming
                        # TODO if you revalue other factors you should put here proper value
                        level_factor = self.evaluate_edit_distance(splittedFindingLevels[count], splittedProductLevels[
                            0])  #+ len(splittedFindingLevels)
                        print("%%%%%%%")
                        print("Version from findings:\t" + str(splittedFindingLevels[count]))
                        print("Version from product levels:\t" + str(splittedProductLevels[0]))
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        print("Levenstein dist of level: " + str(lev_dist_of_lvl))
                        print("%%%%%%%")
                        #TODO Decide about acceptable distance to count as match
                        if lev_dist_of_lvl <= self.lvlLengthList[-1] + SUP.tolerance_factor:
                            try:
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                            except KeyError:
                                self.verValidationsDict[key] = []
                                self.verValidationsDict[key].append({str(splittedFindingLevels[count]).replace('[' ,'').replace(']' ,'').replace('\'', '') : lev_dist_of_lvl})
                    print(self.verValidationsDict)
                # Case when extracted and expected version name have same count of levels
                elif len(splittedFindingLevels) == len(splittedProductLevels[0]): # or len(splittedFindingLevels) % len(splittedProductLevels) == 0:
                    print("\n>>>>>>>>>>  validation in progress: im in dupa2\n")
                    print("Even one: " + str(splittedFindingLevels) + "\n")
                    print("Second even one: " + str(splittedProductLevels[0]) + "\n")
                    lev_dist_of_lvl = 0
                    if len(splittedProductLevels) > 1:
                        for count in range(len(splittedFindingLevels)):
                            mod_fact = count%len(splittedProductLevels)
                            level_factor = self.evaluate_edit_distance(splittedFindingLevels[count],
                                                                       splittedProductLevels[mod_fact]) * (len(splittedFindingLevels) - count)
                            lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                            print("%%%%%%%")
                            print("Version from findings:\t" + str(splittedFindingLevels[count]))
                            print("Version from product levels:\t" + str(splittedProductLevels[mod_fact]))
                            print("%%%%%%%")
                    else:
                        for item in splittedFindingLevels:
                            level_factor = self.evaluate_edit_distance(item, splittedProductLevels[0])
                            lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                            print("Version from findings:\t" + str(item))
                            print("Version from product levels:\t" + str(splittedProductLevels[0]))
                            print("%%%%%%%")

                    self.add_matches(lev_dist_of_lvl, ver, key)

                # Case when expected version name has more levels than the extracted
                elif len(splittedFindingLevels) < len(splittedProductLevels[0]):
                    print("\n>>>>>>>>>>  validation in progress: im in dupa3\n")
                    print("Bigger one: " + str(splittedFindingLevels) + "\n")
                    print("Smaller one: " + str(splittedProductLevels[0]) + "\n")
                    lev_dist_of_lvl = 0
                    if len(splittedProductLevels) > 1:
                        for count in range(len(splittedProductLevels)):
                            mod_fact = count % len(splittedFindingLevels)
                            print("----------> Levek porownuje cos takiego:")
                            print("splittedFindingLevels[count]: " + str(splittedFindingLevels[count]))
                            print("splittedProductLevels[mod_fact]: " + str(splittedProductLevels[mod_fact]))
                            level_factor = self.evaluate_edit_distance(splittedFindingLevels[count],
                                                                       splittedProductLevels[mod_fact]) * (len(splittedFindingLevels) - count)
                            lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                            print("%%%%%%%")
                            print("Version from findings:\t" + str(splittedFindingLevels[count]))
                            print("Version from product levels:\t" + str(splittedProductLevels[mod_fact]))
                            print("%%%%%%%")
                    else:
                        for item in splittedFindingLevels:
                            level_factor = self.evaluate_edit_distance(item, splittedProductLevels[0])
                            lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                            print("Version from findings:\t" + str(item))
                            print("Version from product levels:\t" + str(splittedProductLevels[0]))
                            print("%%%%%%%")
                    lev_dist_of_lvl = lev_dist_of_lvl + len(splittedProductLevels) - len(splittedFindingLevels)
                    self.add_matches(lev_dist_of_lvl, ver, key)

                # Case when extracted version name has more levels than the expected
                elif len(splittedFindingLevels) > len(splittedProductLevels[0]):
                    print("\n>>>>>>>>>>  validation in progress: im in dupa4\n")
                    lev_dist_of_lvl = 0
                    for count in range(len(splittedFindingLevels)):
                        mod_fact = count % len(splittedProductLevels)
                        level_factor = self.evaluate_edit_distance(splittedFindingLevels[count],
                                                                   splittedProductLevels[mod_fact]) * (len(splittedFindingLevels) - count)
                        lev_dist_of_lvl = lev_dist_of_lvl + level_factor
                        print("%%%%%%%")
                        print("Version from findings:\t" + str(splittedFindingLevels[count]))
                        print("Version from product levels:\t" + str(splittedProductLevels[mod_fact]))
                        print("%%%%%%%")
                        if(mod_fact == (len(splittedProductLevels) - 1)):
                            self.add_matches(lev_dist_of_lvl, ver, key)
                            lev_dist_of_lvl = 0
                    # print('Sum of level equals: ' + str(lev_dist_of_lvl))

                else:
                    print("\n\n\n\nDON DUPA DUPEONE\n\n\n\n\n\n")


                ver_iter = ver_iter + 1



        #SUP.log_info('\n\nVALIDATION IS OVER!!\nTheres the results:\n')
        #SUP.log_info(str(self.verValidationsDict) + '\n', 'red')
