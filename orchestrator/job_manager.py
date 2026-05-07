import os
import asyncio
from .runner import run
from internal import *
from external.utils.session_manager import SessionManager
from external.crawler.crawl import Crawlers
from external.scanner.scanner import Scanner

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."  ))

class JobManager:
    def __init__(self, config):
        self.config = config
        self.target = config["target"]
        self.journal = config["journal"]
        self.username = config.get("auth", {}).get("username")
        self.password = config.get("auth", {}).get("password")
        self.dir = config.get("url")
        self.wordlist = config.get("wordlist")
        self.sm = SessionManager(domain=self.target, journal=self.journal, username=self.username, password=self.password)

    async def run_crawler(self):
        print("[*] Crawling target...")
        crawler = Crawlers(domain=self.target, journal=self.journal, sm=self.sm)

        loop = asyncio.get_event_loop()
        urls = await loop.run_in_executor(None, crawler.crawl)
        
        # save ke file (sama seperti crawl.py standalone)
        urls_file = "../results/urls.txt"
        os.makedirs("../results", exist_ok=True)
        with open(urls_file, "w", encoding='utf-8') as f:
            for u in urls:
                f.write(u + "\n")

        print(f"[+] {len(urls)} URLs saved to {urls_file}")
        return urls_file, urls

    async def run_internal(self):
        print("[*] Running internal scanner...")

        cmd = f"python main.py {self.dir}"
        result = await run(cmd, cwd=os.path.join(ROOT_DIR, "internal"))
        print(f"[DEBUG] internal exit code: {result['code']}")
        print(f"[DEBUG] internal stdout: {result['stdout']}")
        print(f"[DEBUG] internal stderr: {result['stderr']}")
        return result

    async def run_external_custom(self, urls_file=None, urls=None):
        print("[*] Running custom external scanner...")

        print("[*] Re-authenticating before scan...")
        endpoints = []
        if urls_file and os.path.exists(urls_file):
            with open(urls_file, encoding='utf-8') as f:  # ← fix 1
                endpoints = [l.strip() for l in f if l.strip()]

        scanner = Scanner(session_manager=self.sm)
        findings = scanner.run(
            endpoints=urls or endpoints,
            base_url=self.target,
            journal=self.journal,
        )

        import json
        os.makedirs("../results", exist_ok=True)
        with open("../results/scanner.json", "w", encoding='utf-8') as f:  # ← fix 2
            json.dump(findings, f, indent=2, ensure_ascii=False)

        print(f"[+] {len(findings)} findings saved to results/scanner.json")
        return {"code": 0, "findings": findings}
    
    async def run_nuclei(self, urls_file):
        print("[*] Running nuclei via external_socket...")

        header = f'-H "Cookie: {self.session}"' if self.session else ""

        cmd = f"""
        nuclei -l {urls_file} -json -o ../results/nuclei.json {header}
        """

        return await run(cmd, cwd="../external_socket")
    
    async def run_gobuster(self, urls_file):
        print("[*] Running gobuster...")

        cmd = f"""
        gobuster dir -u {self.target} -w -o ../results/gobuster.txt
        """

        return await run(cmd, cwd="../external_socket")

    async def execute(self):
        urls_file = None
        urls = []

        # 1. crawler
        if self.config["scans"].get("crawler"):
            urls_file, urls = await self.run_crawler()

        if not urls_file:
            urls_file = "../results/urls.txt"
            with open(urls_file, "w", encoding='utf-8') as f:
                f.write(self.target)

        tasks = []
        tasks_names = []

        # 2. internal
        if self.config["scans"].get("internal"):
            tasks.append(self.run_internal())
            tasks_names.append("internal")

        # 3. external custom
        if self.config["scans"].get("external_custom"):
           tasks.append(self.run_external_custom(urls_file, urls))
           tasks_names.append("external_custom")

        # 4. nuclei
        #if self.config["scans"]["external_nuclei"]:
        #    tasks.append(self.run_nuclei(urls_file))
        #    tasks_names.append("nuclei")

        #5. gobuster
        #if self.config["scans"].get("gobuster"):
        #    tasks.append(self.run_gobuster(urls_file))
        #    tasks_names.append("gobuster")

        # 🔥 paralel execution
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            name = tasks_names[i] if i < len(tasks_names) else f"task_{i}"
            if isinstance(result, Exception):
                import traceback
                print(f"[!] {name} gagal: {result}")
                traceback.print_exception(type(result), result, result.__traceback__) 

        return results