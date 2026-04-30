import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from .crawlers import Crawlers

if __name__ == "__main__":
    domain = sys.argv[1]
    journal = sys.argv[2]
    username = sys.argv[3] if len(sys.argv) > 3 else None
    password = sys.argv[4] if len(sys.argv) > 4 else None

    crawler = Crawlers(domain, journal, username=username, password=password)
    urls = crawler.crawl()

    os.makedirs("../../results", exist_ok=True)
    with open("../../results/urls.txt", "w") as f:
        for u in urls:
            f.write(u + "\n")
    print("Total Endpoints", len(urls))
    print(f"[+] {len(urls)} URLs saved to results/urls.txt")