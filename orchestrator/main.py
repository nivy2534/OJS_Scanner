import json
import asyncio
import os

from job_manager import JobManager
from aggregator import aggregate


def load_config():
    with open("config.json") as f:
        return json.load(f)


async def main():
    os.makedirs("../results", exist_ok=True)

    config = load_config()

    manager = JobManager(config)

    await manager.execute()

    findings = aggregate()

    print("\n=== FINAL FINDINGS ===")
    for f in findings:
        print(f)


if __name__ == "__main__":
    asyncio.run(main())