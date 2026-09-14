import functools, signal, time
from dataclasses import dataclass
from logger import agent_logger

@dataclass
class AgentBudget:
    max_steps: int = 20 # max tool calls
    max_seconds: float = 120.0 # wall-clock timeout
    max_tokens: int = 50000 # total token budget
    step_count: int = 0
    token_count: int = 0
    start_time: float = 0.0

    def start(self): 
        self.start_time = time.time()
        agent_logger.info(f"AgentBudget started: max_steps={self.max_steps}, max_seconds={self.max_seconds}, max_tokens={self.max_tokens}")

    def check(self) -> str | None:
        """Returns an error string if any budget exceeded."""
        if self.step_count >= self.max_steps:
            agent_logger.warning(f"Budget check failed: Step limit reached ({self.step_count}/{self.max_steps})")
            return f"Step limit reached ({self.max_steps})"
        elapsed = time.time() - self.start_time
        if elapsed > self.max_seconds:
            agent_logger.warning(f"Budget check failed: Timeout ({elapsed:.1f}s > {self.max_seconds}s)")
            return f"Timeout ({elapsed:.1f}s)"
        if self.token_count > self.max_tokens:
            agent_logger.warning(f"Budget check failed: Token budget exceeded ({self.token_count}/{self.max_tokens})")
            return f"Token budget exceeded ({self.token_count})"
        agent_logger.debug(f"Budget check passed: steps={self.step_count}, tokens={self.token_count}, elapsed={elapsed:.1f}s")
        return None

def with_timeout(seconds: int):
    """Decorator to add a timeout to any tool function."""
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            def _timeout(signum, frame):
                agent_logger.error(f"Function {fn.__name__} timed out after {seconds}s")
                raise TimeoutError(f'{fn.__name__} timed out')
            signal.signal(signal.SIGALRM, _timeout)
            signal.alarm(seconds)
            try: 
                result = fn(*args, **kwargs)
                agent_logger.debug(f"Function {fn.__name__} completed within timeout")
                return result
            finally: signal.alarm(0)
        return wrapper
    return decorator