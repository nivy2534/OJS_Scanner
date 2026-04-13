from external.scanner import *
from internal import *
from orchestrator import main as run_orchestrator
import asyncio
def main():
    asyncio.run(run_orchestrator())

if __name__ == "__main__":
    main()