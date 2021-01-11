import unittest

import process_urls


class ProcessUrlsTest(unittest.TestCase):

    def test_score_zero(self):
        keywords = {'banana': 10, 'msite': 9, 'com': 0}
        url = 'http://mysite.com'
        score = process_urls.calculate_score(url, keywords)
        self.assertEqual(score, 0)

    def test_score_non_zero(self):
        keywords = {'banana': 10, 'site': 1, 'magic': 2}
        url = 'http://thisismagicsite.com/verymagic/'

        score = process_urls.calculate_score(url, keywords)
        self.assertEqual(score, 5)

    def test_extract_tld_basic(self):
        tld = process_urls.extract_tld('http://basicsite.com')
        self.assertEqual(tld, '.com')

    def test_extract_tld_with_slash(self):
        tld = process_urls.extract_tld('http://basicsite.com/')
        self.assertEqual(tld, '.com')

    def test_extract_tld_with_path_and_https(self):
        tld = process_urls.extract_tld('https://basicsite.com/page=mysite.php&password=1&include=lfi.php')
        self.assertEqual(tld, '.com')

    def test_extract_tld_hierarchy(self):
        tld = process_urls.extract_tld('https://my.site.com.google.net')
        self.assertEqual(tld, '.net')

    def test_extract_tld_missin_tld(self):
        tld = process_urls.extract_tld('http://127.0.0.1/file=index.php')
        self.assertEqual(tld, None)

    def test_mark_false(self):
        self.assertEqual(process_urls.mark(0), False)

    def test_mark_true(self):
        self.assertEqual(process_urls.mark(9), True)


if __name__ == '__main__':
    unittest.main()
