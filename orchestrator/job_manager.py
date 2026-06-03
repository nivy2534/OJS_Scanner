import os
import asyncio
import subprocess
import shutil
import json
from .runner import run
from datetime import datetime
from internal.main import scan as run_semgrep
from external.utils.session_manager import SessionManager
from external.crawler.crawl import Crawlers
from external.scanner.scanner import Scanner
from server.http_server import HttpServer
from reporter import load_all_findings, generate_report, notify_if_needed
from reporter.alert_buffer import get_alert_buffer


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.abspath(os.path.join(BASE_DIR, ".."  ))

class JobManager:
    def __init__(self, config):
        self.config = config
        self.target = config["target"]
        self.journal = config["journal"]
        self.username = config.get("auth", {}).get("username")
        self.password = config.get("auth", {}).get("password")
        self.dir = config.get("ojs_root")
        self.wordlist = config.get("wordlist")
        # self.sm = SessionManager(domain=self.target, journal=self.journal, username=self.username, password=self.password)
        self.server = HttpServer()
        self.server.set_scan_handler(self._handle_agent_scan)

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
        """Jalankan internal scan langsung — reuse scan() yang sudah ada."""
        print("[*] Running internal scanner (Semgrep)...")

        ojs_root = self.config.get("ojs_root", self.dir)
        if not ojs_root:
            print("[!] ojs_root tidak dikonfigurasi, skip")
            return {"code": 1, "findings": []}

        loop = asyncio.get_event_loop()
        try:
            # scan() blocking, jalankan di executor biar tidak block event loop
            findings = await loop.run_in_executor(None, run_semgrep, ojs_root)
            return {"code": 0, "findings": findings}
        except Exception as e:
            print(f"[!] Internal scan error: {e}")
            return {"code": 1, "error": str(e), "findings": []}

    def _copy_from_container(self, relative_path: str, staging_dir: str) -> tuple[bool, str]:
        container = self.config.get("ojs_container", "pkp_app_ojs")

        if relative_path == ".":
            src_path  = "pkp_app_ojs:/var/www/html"
            dest_name = "ojs_full"
        else:
            src_path  = f"pkp_app_ojs:/var/www/html/{relative_path.lstrip('/')}"
            dest_name = os.path.basename(relative_path.rstrip("/"))

        os.makedirs(staging_dir, exist_ok=True)
        print(f"[*] Copying {src_path}...")

        result = subprocess.run(
            ["docker", "cp", src_path, os.path.join(staging_dir, dest_name)],
            capture_output=True, text=True,
        )

        if result.returncode != 0:
            print(f"[!] Copy gagal: {result.stderr}")
            return False, ""

        abs_path = os.path.join(staging_dir, dest_name)
        print(f"[+] Copy selesai: {abs_path}")
        return True, abs_path

    def _handle_agent_scan(self, payload: dict) -> dict:
        relative_path = payload.get("path", "")
        event         = payload.get("event", "manual")
    
        print(f"[*] Agent scan: {relative_path} [{event}]")
    
        # ── Buat scan dir ────────────────────────────────────────────────────────
        ts         = datetime.now().strftime("%Y%m%d_%H%M%S")
        scan_label = "full_scan" if relative_path == "." else \
                    relative_path.replace("/", "_").strip("_")
    
        scan_dir    = os.path.abspath(os.path.join(
            os.path.dirname(__file__), "..", "..", "results", "scans",
            f"scan_{ts}_{scan_label}"
        ))
        staging_dir = os.path.join(scan_dir, "_staging")
        os.makedirs(scan_dir, exist_ok=True)
    
        # ── Copy dari container ──────────────────────────────────────────────────
        success, abs_path = self._copy_from_container(relative_path, staging_dir)
        if not success:
            return {"error": "Gagal copy dari container", "findings": []}
    
        # ── Semgrep scan ─────────────────────────────────────────────────────────
        try:
            sast_findings = run_semgrep(abs_path)
        except Exception as e:
            print(f"[!] Semgrep error: {e}")
            return {"error": str(e), "findings": []}
        finally:
            shutil.rmtree(staging_dir, ignore_errors=True)
            print(f"[*] Staging cleaned")
    
        # ── Flush alert buffer (runtime content injection alerts) ────────────────
        runtime_alerts = get_alert_buffer().flush()
    
        if runtime_alerts:
            print(f"[*] Menggabungkan {len(sast_findings)} SAST findings + "
                f"{len(runtime_alerts)} runtime alerts")
        
        # Gabungkan semua findings
        all_findings = sast_findings + runtime_alerts
    
        # ── Summary ──────────────────────────────────────────────────────────────
        by_severity: dict[str, int] = {}
        for f in all_findings:
            sev = f.get("severity", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
    
        # Tentukan scan_types berdasarkan apa yang ada
        scan_types = []
        if sast_findings:
            scan_types.append("sast")
        if runtime_alerts:
            scan_types.append("dast_runtime")
    
        result = {
            "findings":       all_findings,
            "sast_count":     len(sast_findings),
            "runtime_count":  len(runtime_alerts),
            "summary":        {"total": len(all_findings), "by_severity": by_severity},
            "scanned_path":   relative_path,
            "event":          event,
            "ts":             ts,
        }
    
        # ── Save findings.json ───────────────────────────────────────────────────
        findings_path = os.path.join(scan_dir, "findings.json")
        with open(findings_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    
        print(f"[+] Findings saved: {findings_path}")
        print(f"    SAST    : {len(sast_findings)} finding(s)")
        print(f"    Runtime : {len(runtime_alerts)} alert(s)")
        print(f"    Total   : {len(all_findings)} finding(s)")
    
        # ── Auto generate report ─────────────────────────────────────────────────
        if all_findings:
            print(f"[*] Generating report untuk {len(all_findings)} finding(s)...")
            try:
                report_path = generate_report(
                    findings   = all_findings,
                    target     = self.target,
                    scan_types = scan_types,
                    output_dir = scan_dir,
                )
                if report_path:
                    print(f"[+] Report: {report_path}")
                    result["report_path"] = report_path
                    notify_if_needed(all_findings, report_path, self.target)
            except Exception as e:
                print(f"[!] Report error: {e}")
        else:
            print(f"[*] Clean scan — tidak ada findings")
    
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
    
    async def run_http_server(self):
        if self.server._is_running():
            print("[*] HTTP server is already running.")
            return {"code": 0, "message": "HTTP server already running"}
        try:
            print("[*] Starting HTTP server...")
            self.server.start()
            scans = self.config.get("scans", {})
            only_server = not any(
                scans.get(s) for s in ["crawler", "internal", "external_custom"]
            )
            if only_server:
                print("[*] Waiting for agent requests... (Ctrl+C untuk stop)")
                try:
                    while True:
                        await asyncio.sleep(1)
                except (KeyboardInterrupt, asyncio.CancelledError):
                    self.server.stop()
            
            return {"code": 0}
        except Exception as e:
            print(f"[!] Failed to start HTTP server: {e}")
            return {"code": 1, "error": str(e)}

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

        if self.config["scans"].get("http_server"):
            tasks.append(self.run_http_server())
            tasks_names.append("http_server")

        # 4. nuclei
        #if self.config["scans"]["external_nuclei"]:
        #    tasks.append(self.run_nuclei(urls_file))
        #    tasks_names.append("nuclei")

        #5. gobuster
        #if self.config["scans"].get("gobuster"):
        #    tasks.append(self.run_gobuster(urls_file))
        #    tasks_names.append("gobuster")

        # 🔥 paralel execution
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for i, result in enumerate(results):
                name = tasks_names[i] if i < len(tasks_names) else f"task_{i}"
                if isinstance(result, Exception):
                    if isinstance(result, (asyncio.CancelledError, KeyboardInterrupt)) and name=="http_server":
                        print(f"[*] {name} stopped.")
                        self.server.stop()
                        continue
                    import traceback
                    print(f"[!] {name} gagal: {result}")
                    traceback.print_exception(type(result), result, result.__traceback__) 
            findings, scan_types = load_all_findings()
            report_path = generate_report(findings, target=self.target, scan_types=scan_types)
            notify_if_needed(findings, report_path, self.target)
        except Exception as e:
            print(f"[!] Error during scan execution: {e}")
            return
        return results
