import json
import re
import sqlite3
import urllib.request
from pathlib import Path

import yaml


class DBAccess(object):
    db_path = 'phising_urls.db'

    def __init__(self):
        self.connection = sqlite3.connect(self.db_path)
        self.create_table()

    def create_table(self):
        sql_create_table = '''CREATE TABLE IF NOT EXISTS urls (
                                id integer PRIMARY KEY,
                                url text NOT NULL,
                                url_contain_keyword integer NOT NULL,
                                suspicious_tld integer NOT NULL,
                                keyword_score integer NOT NULL
                           );'''

        cursor = self.connection.cursor()
        cursor.execute(sql_create_table)
        self.connection.commit()

    def write_db(self, to_write):
        sql_isnert = '''INSERT INTO urls(id,url,url_contain_keyword,suspicious_tld,keyword_score)
                        VALUES(?,?,?,?,?)'''

        self.create_table()
        cursor = self.connection.cursor()
        cursor.executemany(sql_isnert, to_write)
        self.connection.commit()

    def close_db(self):
        self.connection.close()


class SuspiciousPatterns(object):

    source_yaml_file = Path('suspicious.yaml')

    def __init__(self):
        with open(self.source_yaml_file) as source:
            self.data = yaml.load(source, Loader=yaml.FullLoader)

    def get_keywords(self):
        return self.data['keywords']

    def get_tlds(self):
        return self.data['tlds'].keys()


class PhishingSites(object):

    source_json = Path('phising_sites_source.json')
    source_url = 'http://data.phishtank.com/data/online-valid.json'

    def read_data(self, download_new_json_source=False):

        if download_new_json_source or not self.source_json.exists():
            urllib.request.urlretrieve(self.source_url, self.source_json)

        with open(self.source_json, 'r') as source:
            return json.load(source)

    def get_id_url_dict(self):
        data = self.read_data()
        # not checking duplicities, if we do not believe in unique 'phish_id' add var c=0 and instead
        # k['phish_id'] paste ++c
        return {k['phish_id']: k['url'] for k in data}


def calculate_score(url, keywords):
    score = 0

    for keyword in keywords:
        score += keywords[keyword] * len([m for m in re.finditer(keyword, url)])

    return score


def extract_tld(url):
    tld_pattern = 'https?:\/\/.+?(\.[a-z]+)?(?:\/|$).*'
    match = re.search(tld_pattern, url)
    return match.group(1)


def mark(score):
    return True if score > 0 else False


def process_urls():
    suspicious_patterns = SuspiciousPatterns()
    phishing_sites = PhishingSites()

    keywords = suspicious_patterns.get_keywords()
    tlds = {tld: 1 for tld in suspicious_patterns.get_tlds()}

    to_db = []

    for id, url in phishing_sites.get_id_url_dict().items():
        keyword_score = calculate_score(url, keywords)

        tld = extract_tld(url)
        if tld is None:
            print('Cannot guess tld for url ' + url)
            tld_score = 0
        else:
            tld_score = calculate_score(tld, tlds)

        to_db.append([id, url, mark(keyword_score), mark(tld_score), keyword_score])

    db_access = DBAccess()
    db_access.write_db(to_db)
    db_access.close_db()


if __name__ == '__main__':
    process_urls()
