import Supplies as SUP


class VendorCveAnalizer(object):
    # Class analyses extracted CVE Summaries.
    # Object of class contains all summaries connected with given producent
    def __init__(self, vendor):
        self.venName = SUP.parse_vendor_name(vendor)
        self.venSummaries = {}

    def find_all_vendors_cve(self, source_dict):
        # Method extracts CVE entries with chosen vendor, based on Summary mention
        for key in source_dict:
            if self.venName.lower().strip() in source_dict[key].lower().strip():
                self.venSummaries[key] = source_dict[key]

    def find_all_products_cve(self, product):
        # Method extracts CVE entries with chosen product, based on Summary mention
        product_summ_dict = {}
        for key in self.venSummaries:
            if product.lower().strip() in self.venSummaries[key].lower().strip():
                product_summ_dict[key] = self.venSummaries[key]
        return product_summ_dict

    '''
    def parse_vendor_name(self, vendor_name):
        #Method deletes unneccessary elements from vendor's name
        new_name_elements = re.split(special_char_pattern, str(vendor_name).lower().strip())
        new_name = ''
        for element in new_name_elements:
            if str(element) not in additionals:
                new_name = new_name + str(element)
        log_info('Vendors name: ' + vendor_name + ' was successfully changed to: ' + new_name)
        return new_name        
    '''