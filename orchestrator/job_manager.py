import asyncio
from runner import run
from external.scanner import main as run_external_scanner 
from internal import *

class JobManager:
    def __init__(self, config):
        self.config = config
        self.target = config["target"]
        self.cookie = config.get("auth", {}).get("cookie")

    async def run_crawler(self):
        print("[*] Crawling target...")

        return "../results/urls.txt"

    async def run_internal(self):
        print("[*] Running internal scanner...")

        cmd = "python3 main.py"
        return await run(cmd, cwd="../internal")

    async def run_external_custom(self):
        print("[*] Running custom external scanner...")

        cmd = f"python3 scanner/scanner.py {self.target}"
        return await run(cmd, cwd="../external")

    async def run_nuclei(self, urls_file):
        print("[*] Running nuclei via external_socket...")

        header = f'-H "Cookie: {self.cookie}"' if self.cookie else ""

        cmd = f"""
        nuclei -l {urls_file} -json -o ../results/nuclei.json {header}
        """

        return await run(cmd, cwd="../external_socket")

    async def execute(self):
        urls_file = None

        # 1. crawler
        if self.config["scans"]["crawler"]:
            urls_file = await self.run_crawler()

        if not urls_file:
            urls_file = "../results/urls.txt"
            with open(urls_file, "w") as f:
                f.write(self.target)

        tasks = []

        # 2. internal
        if self.config["scans"]["internal"]:
            tasks.append(self.run_internal())

        # 3. external custom
        if self.config["scans"]["external_custom"]:
            tasks.append(self.run_external_custom())

        # 4. nuclei
        if self.config["scans"]["external_nuclei"]:
            tasks.append(self.run_nuclei(urls_file))

        # 🔥 paralel execution
        results = await asyncio.gather(*tasks, return_exceptions=True)

        return results