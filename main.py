from orchestrator.main import main as orchestrator_main
import asyncio


if __name__ == "__main__":
    try:
        asyncio.run(orchestrator_main())
    except KeyboardInterrupt:
        print("\n[*] Stopped.")