import sys
import resource
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
import time

class Sandbox:
    """Basic code execution sandbox with resource limits"""
    def __init__(self, timeout=5, memory=256):
        self.timeout = timeout
        self.memory_limit = memory * 1024 * 1024  # Convert MB to bytes
        self.allowed_modules = {'math', 'datetime', 'collections'}

    def validate(self, code: str) -> bool:
        """Check code safety before execution"""
        if any(blacklisted in code for blacklisted in [
            'os.', 'sys.', 'open(', 'exec', 'eval', 'shutil', 'subprocess'
        ]):
            return False
        return True

    def execute(self, code: str) -> tuple:
        """Execute code with resource constraints"""
        output = StringIO()
        start_time = time.time()
        
        # Set resource limits
        resource.setrlimit(resource.RLIMIT_AS, 
                          (self.memory_limit, self.memory_limit))
        resource.setrlimit(resource.RLIMIT_CPU, 
                          (self.timeout, self.timeout))

        try:
            with redirect_stdout(output), redirect_stderr(output):
                exec(code, {'__builtins__': None}, {
                    m: __import__(m) for m in self.allowed_modules
                })
            return True, output.getvalue()
        except Exception as e:
            return False, f"SandboxError: {str(e)}"
        finally:
            resource.setrlimit(resource.RLIMIT_AS, 
                              (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
            resource.setrlimit(resource.RLIMIT_CPU, 
                              (resource.RLIM_INFINITY, resource.RLIM_INFINITY))