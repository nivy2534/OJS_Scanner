import asyncio

async def run(cmd, cwd=None):
    process = await asyncio.create_subprocess_shell(
        cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()

    return {
        "code": process.returncode,
        "stdout": stdout.decode(),
        "stderr": stderr.decode()
    }