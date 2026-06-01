import asyncio

async def run(cmd, cwd=None):
    process = await asyncio.create_subprocess_shell(
        cmd,
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )

    stdout, stderr = await process.communicate()
    
    stdout_str = stdout.decode()
    stderr_str = stderr.decode()

    if stderr_str:
        print(stderr_str, end="")
    if stdout_str:
        print(stdout_str, end="")

    return {
        "code": process.returncode,
        "stdout": stdout.decode(),
        "stderr": stderr.decode()
    }