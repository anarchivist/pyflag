""" This module implements some tests specific for unicode handling """
import pyflag.tests

class UnicodeTest(pyflag.tests.ScannerTest):
    """ Test Unicode handling """
    test_case = "PyFlagTestCase"
    test_file = "unicode.E01"
    subsystem = "EWF"
