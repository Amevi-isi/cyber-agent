import anthropic
from tools import get_tool_schemas, execute_tool
from logger import agent_logger

client = anthropic.Anthropic()

def agent_turn(messages: list, system: str) -> tuple[list, bool]:
    """Run one agent turn. Returns (updated_messages, is_done)."""
    agent_logger.debug(f"Agent turn started with {len(messages)} messages")
    response = client.messages.create(
        model="claude-opus-4-6",
        max_tokens=4096,
        system=system,
        tools=get_tool_schemas(),
        messages=messages
    )

    new_messages, tool_results = [], []

    for block in response.content:
        if block.type == "text":
            new_messages.append({"role": "assistant", "content": response.content})
            agent_logger.debug(f"Agent turn received text response")

        elif block.type == "tool_use":
            agent_logger.info(f"Tool call: {block.name}")
            try:
                result = execute_tool(block.name, block.input)
                agent_logger.debug(f"Tool {block.name} executed successfully")
            except Exception as e:
                result = f"Error: {e}"
                agent_logger.error(f"Tool {block.name} failed: {e}")
            
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": block.id,
                "content": str(result)
            })

    if tool_results:
        new_messages.append({"role": "user", "content": tool_results})

    is_done = response.stop_reason == "end_turn" and not tool_results
    agent_logger.debug(f"Agent turn completed: is_done={is_done}, tool_results={len(tool_results)}")
    return messages + new_messages, is_done