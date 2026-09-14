from dataclasses import dataclass, field
from typing import Literal
from logger import agent_logger

MessageRole = Literal['user', 'assistant']

@dataclass
class Message:
    role: MessageRole
    content: str

@dataclass
class AgentMemory:
    """Manages conversation history for the agent."""
    messages: list[Message] = field(default_factory=list)
    max_messages: int = 50 # prevent context overflow

    def add(self, role: MessageRole, content: str):
        self.messages.append(Message(role=role, content=content))
        agent_logger.debug(f"Memory add: role={role}, message_count={len(self.messages)}")
        if len(self.messages) > self.max_messages:
            self.messages = self.messages[-self.max_messages:]
            agent_logger.debug(f"Memory trimmed to {self.max_messages} messages")

    def to_api_format(self) -> list[dict]:
        result = [{'role': m.role, 'content': m.content} for m in self.messages]
        agent_logger.debug(f"Memory to_api_format: {len(result)} messages")
        return result

    def summarize_if_long(self, client, threshold=30):
        """Compress old history to save tokens."""
        if len(self.messages) < threshold: 
            agent_logger.debug(f"Memory summarize skipped: {len(self.messages)} < {threshold}")
            return
        agent_logger.info(f"Summarizing memory: {len(self.messages)} messages")
        old, recent = self.messages[:-10], self.messages[-10:]
        old_text = "\n".join(f"{m.role}: {m.content}" for m in old)
        summary = client.messages.create(
            model="claude-haiku-4-5-20251001", max_tokens=256,
            messages=[{"role": "user", "content": f"Summarize:\n{old_text}"}]
        ).content[0].text
        self.messages = [Message('user', f'[Earlier]: {summary}')] + recent
        agent_logger.info(f"Memory summarized: now {len(self.messages)} messages")