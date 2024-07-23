import unittest
from lambda_function import determine_translation
from test_data import *

class TestStringMethods(unittest.TestCase):
    def run_test(self, testData):
        translation_data = determine_translation(
            testData['quote'], 
            build_test_data(testData['english_text']),
            build_test_data(testData['spanish_text']))
        self.assertEqual(testData['expected'], translation_data)

    def test_determine_translation_simple(self):
        self.run_test(SIMPLE_TEST)

    def test_determine_translation_full_paragraph(self):
        self.maxDiff = None
        self.run_test(FULL_PARAGRAPH)

    def test_determine_translation_multi_paragraph(self):
        self.maxDiff = None
        self.run_test(MULTI_PARAGRAPH)

    def test_determine_translation_mid_paragraph(self):
        self.maxDiff = None
        self.run_test(MID_PARAGRAPH)

    def test_determine_translation_match_capitalization(self):
        self.run_test(MATCH_CAPITALIZATION)

    def test_determine_translation_last_paragraph(self):
        self.run_test(LAST_PARAGRAPH)

if __name__ == '__main__':
    unittest.main()