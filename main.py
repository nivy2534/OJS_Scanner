import requests
from crawler import Crawler
from scanner import Scanner
from rule import Rule
from pw_login import playwright_login as pl

def main():
    domain = "http://localhost:8081"
    journal = "coba"
    username = "admin"
    password = "OJS_Scanner_1"
    crawler = Crawler(domain, journal)

    endpoints = crawler.crawl(username, password)

    print("Total Endpoints", len(endpoints))

if __name__ == "__main__":
    main()