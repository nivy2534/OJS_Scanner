from crawler.crawler import Crawler
from crawler.crawlers import Crawlers
from scanner.scanner import Scanner
from scanner.rule_loader import load_rule 
from crawler.pw_login import playwright_login as pl

def main():
    domain = "http://localhost:8081"
    journal = "coba"
    username = "admin"
    password = "OJS_Scanner_1"
    
    auth_file = pl(domain, journal, username, password)
    
    crawler = Crawler(domain,journal)
    endpoints = crawler.crawl(auth_file)

    print("Total Endpoints", len(endpoints))
    #crawl("http://localhost:8081", "coba")

#if __name__ == "__main__":    
#    main()

if __name__ == "__main__":
    domain = "http://localhost:8081"
    journal = "coba"
    username = "admin"
    password = "OJS_Scanner_1"
    crawler = Crawlers(
        domain="http://localhost:8081",
        journal="coba", username=username, password=password
    )

    urls = crawler.crawl()

    for u in urls:
        print(u)

def crawl(domain, journal, cookies=None, username=None, password=None):
    crawler = Crawlers(domain,journal)
    endpoints = crawler.crawl(cookies, username, password)
    print("Total Endpoints", len(endpoints))
    print(endpoints)
def scan(endpoints, rules):
    pass
