"""Real, fixed-command dependency check; not a security scanner."""
import asyncio
import os
import signal
import sys

from secram.tools.base import ToolAdapter, ToolRequest, ToolResult, ToolStatus


class PythonRuntimeAdapter(ToolAdapter):
    name = "python-runtime"

    def __init__(self) -> None:
        self._tested = False

    def probe(self) -> ToolStatus:
        return ToolStatus(self.name, os.path.isfile(sys.executable), True, self._tested,
                          sys.platform == "linux", "Yerel Python çalışma zamanı; güvenlik taraması değildir.",
                          executable=sys.executable, version=sys.version.split()[0])

    def validate(self, request: ToolRequest) -> None:
        if sys.platform != "linux":
            raise RuntimeError("Phase 1 supports Linux only")
        if request.operation != "version" or request.target is not None or request.parameters:
            raise ValueError("Only fixed, parameter-free local version checks are supported")
        if not 0.1 <= request.timeout <= 30:
            raise ValueError("Timeout must be between 0.1 and 30 seconds")

    async def run(self, request: ToolRequest) -> ToolResult:
        self.validate(request)
        process = await asyncio.create_subprocess_exec(
            sys.executable, "--version", stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, start_new_session=True,
        )
        try:
            async with asyncio.timeout(request.timeout):
                stdout, stderr = await process.communicate()
        except BaseException:
            if process.returncode is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            await process.wait()
            raise
        out = stdout.decode("utf-8", errors="replace").strip()
        err = stderr.decode("utf-8", errors="replace").strip()
        self._tested = process.returncode == 0 and (out or err).startswith("Python ")
        result = ToolResult(self.name, process.returncode, out, err,
                            {"version": out or err, "executable": sys.executable})
        if not self._tested:
            raise RuntimeError(f"Python runtime check failed: {err or out}")
        return result

    def normalize(self, result: ToolResult) -> dict:
        return {"tool": result.tool, "returncode": result.returncode,
                "stdout": result.stdout, "stderr": result.stderr, **result.data}
