import inspect, json
from typing import Callable, Any
from logger import agent_logger

_tools: dict[str, Callable] = {}

def tool(fn: Callable) -> Callable:
    """Decorator to register a function as an agent tool."""
    _tools[fn.__name__] = fn
    agent_logger.debug(f"Tool registered: {fn.__name__}")
    return fn

def get_tool_schemas() -> list[dict]:
    """Generate JSON schemas for all registered tools."""
    schemas = []
    for name, fn in _tools.items():
        sig = inspect.signature(fn)
        props, required = {}, []
        for pname, param in sig.parameters.items():
            props[pname] = {"type": "string", "description": f"Parameter: {pname}"}
            if param.default is inspect.Parameter.empty:
                required.append(pname)
        schemas.append({
            "name": name, 
            "description": fn.__doc__ or "",
            "input_schema": {"type": "object", "properties": props, "required": required}
        })
    return schemas

def execute_tool(name: str, args: dict) -> Any:
    """Execute a registered tool by name."""
    if name not in _tools:
        agent_logger.error(f"Unknown tool attempted: {name}")
        raise ValueError(f"Unknown tool: {name}")
    agent_logger.info(f"Executing tool: {name} with args: {args}")
    result = _tools[name](**args)
    agent_logger.debug(f"Tool {name} executed successfully")
    return result

# Define tools using the decorator
@tool
def web_search(query: str) -> str:
    """
    Search the web for real-time information, facts, or documentation.
    Returns a formatted list of results with titles, snippets, and source URLs.
    """
    import os
    agent_logger.debug(f"web_search called with query: {query}")
    try:
        import serpapi

        api_key = os.getenv("SERP_API_KEY")
        if not api_key:
            agent_logger.warning("SERP_API_KEY not found in environment")
            return "Error: SERP_API_KEY not found in environment variables."

        params = {
            "q": query,
            "num": 5,
            "api_key": api_key,
            "engine": "google",
            "hl": "fr",
            "gl": "fr"
        }

        search = serpapi.GoogleSearch(params)
        results = search.get_dict().get("organic_results", [])
        agent_logger.debug(f"web_search returned {len(results)} results")

        if not results:
            agent_logger.info(f"No results found for query: {query}")
            return f"No results found for: {query}"

        formatted = [f"### Search Results for: {query}\n"]
        for i, res in enumerate(results, 1):
            title = res.get('title', 'No Title')
            link = res.get('link', 'No Link')
            snippet = res.get('snippet', 'No snippet available.')
            formatted.append(f"{i}. **{title}** ({link})\n   - {snippet}\n")

        return "\n".join(formatted)
    except Exception as e:
        agent_logger.error(f"web_search failed: {e}")
        return f"Error: web_search failed — {e}"

@tool
def read_file(path: str) -> str:
    """Read and return the contents of a local file."""
    agent_logger.debug(f"read_file called with path: {path}")
    try:
        with open(path) as f: 
            content = f.read()
        agent_logger.info(f"Successfully read file: {path}")
        return content
    except Exception as e:
        agent_logger.error(f"Failed to read file {path}: {e}")
        raise

@tool
def run_python(code: str) -> str:
    """Execute Python code and return stdout."""
    agent_logger.debug(f"run_python called with code length: {len(code)}")
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf): 
        exec(code, {})
    result = buf.getvalue() or "(no output)"
    agent_logger.debug(f"run_python executed, output length: {len(result)}")
    return result