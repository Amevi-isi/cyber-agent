import anthropic, time
from dataclasses import dataclass, field
from tools import get_tool_schemas, execute_tool
from guards import AgentBudget
from memory import AgentMemory
from logger import agent_logger
from system_prompt import AGENT_SYSTEM_PROMPT

import os
from pathlib import Path
from dotenv import load_dotenv
load_dotenv(Path(__file__).resolve().parent.parent.parent / ".env")



@dataclass
class AgentResult:
    answer: str
    steps_taken: int
    tokens_used: int
    duration_s: float
    tool_calls: list[str] = field(default_factory=list)

class Agent:
    """A minimal but complete AI agent in pure Python."""

    def __init__(self, model='claude-opus-4-6', budget=None, verbose=True):
        self.client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_KEY"))
        self.model = model
        self.budget = budget or AgentBudget()
        self.verbose = verbose

    def _log(self, level: int, msg: str):
        if self.verbose:
            agent_logger.log(level, msg)

    def run(self, goal: str) -> AgentResult:
        """Run the agent on a goal."""
        self.budget.start()
        
        memory = AgentMemory()
        memory.add("user", goal)
        
        tool_calls, total_tokens = [], 0
        self._log(20, f"Goal Started: {goal[:80]}...") # 20 is logging.INFO

        while True:
            budget_err = self.budget.check()
            if budget_err:
                self._log(30, f"Guard triggered: {budget_err}") # 30 is logging.WARNING
                answer = f"Agent stopped: {budget_err}"; break

            response = self.client.messages.create(
                model=self.model, max_tokens=4096,
                system=AGENT_SYSTEM_PROMPT, tools=get_tool_schemas(),
                messages=memory.to_api_format()
            )

            total_tokens += (response.usage.input_tokens + 
                            response.usage.output_tokens)
            self.budget.token_count = total_tokens
            asst = response.content
            
            # The assistant response might contain text + tool_calls, so we add it exactly as provided
            # to respect the anthropic API format. AgentMemory handles custom content types natively.
            memory.add("assistant", asst)
            
            tool_results, final_text = [], ''

            for block in asst:
                if block.type == "text":
                    final_text = block.text
                elif block.type == "tool_use":
                    self.budget.step_count += 1
                    tool_calls.append(block.name)
                    self._log(20, f"Tool Call: {block.name}(...)")
                    try: 
                        result = execute_tool(block.name, block.input)
                        if isinstance(result, str) and result.startswith("Error:"):
                            self._log(40, f"Tool Failure ({block.name}): {result}")
                        else:
                            # Log success and a preview of the output for the traces
                            preview = str(result)[:100].replace('\n', ' ') + ('...' if len(str(result)) > 100 else '')
                            self._log(10, f"Tool Success ({block.name}): {preview}")
                    except Exception as e: 
                        result = f"Error: {e}"
                        self._log(40, f"Tool Exception ({block.name}): {e}")
                        
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": str(result)
                    })

            if tool_results:
                memory.add("user", tool_results)
                continue
            
            answer = final_text; break

        duration = time.time() - self.budget.start_time
        return AgentResult(
            answer=answer,
            steps_taken=self.budget.step_count,
            tokens_used=total_tokens,
            duration_s=duration,
            tool_calls=tool_calls
        )

# ■■ Usage ■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■■
if __name__ == "__main__":
    agent = Agent(verbose=True)
    result = agent.run("Find the top 3 Python web frameworks")
    print(result.answer)
    print(f"Steps: {result.steps_taken} · Tokens: {result.tokens_used}")