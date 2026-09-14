# tools/memory/chroma_tool.py

from ..base import BaseTool

class ChromaTool(BaseTool):
    def __init__(self, collection):
        super().__init__("chroma_tool")
        self.collection = collection

    def run(self, query: str, k=3):
        results = self.collection.query(query_texts=[query], n_results=k)
        return results