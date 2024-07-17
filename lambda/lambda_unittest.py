import unittest
from lambda_function import determine_translation
from test_data import *

class TestStringMethods(unittest.TestCase):
    def run_test(self, testData):
        translation_data = determine_translation(testData['quote'], testData['english_data'], testData['spanish_data'])
        self.assertEqual(testData['expected'], translation_data)

    def test_determine_translation_simple(self):
        self.run_test(SIMPLE_TEST)

    def test_determine_translation_full_paragraph(self):
        self.maxDiff = None
        self.run_test(FULL_PARAGRAPH)

if __name__ == '__main__':
    unittest.main()