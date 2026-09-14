import json


class Memory:

    def __init__(self, max_events=10):
        self.events = []
        self.max_events = max_events

    def add_event(self, event):

        self.events.append(event)

        if len(self.events) > self.max_events:
            self.events.pop(0)

    def get_context(self, query: str = None):

        return "\n".join([str(e) for e in self.events])


class ChromaMemory:
    """Mémoire persistante basée sur ChromaDB avec recherche sémantique."""

    def __init__(
        self,
        persist_dir: str = "./chroma_db",
        collection_name: str = "soc_events",
        k: int = 5,
        chroma_host: str = None,
        chroma_port: int = 8000,
    ):
        import os
        import chromadb as _chromadb
        from tools.memory.chroma import ChromaTool
        host = chroma_host or os.getenv("CHROMA_HOST", "localhost")
        self.client = _chromadb.HttpClient(host=host, port=chroma_port)
        self.collection = self.client.get_or_create_collection(collection_name)
        self.chroma_tool = ChromaTool(self.collection)
        self.k = k
        # Initialise le compteur depuis le nombre d'entrées existantes
        self.event_counter = self.collection.count()

    def add_event(self, event: dict) -> None:
        doc = json.dumps(event, default=str)
        event_id = f"event_{self.event_counter}"
        self.collection.add(documents=[doc], ids=[event_id])
        self.event_counter += 1

    def get_context(self, query: str = None) -> str:
        if self.collection.count() == 0 or query is None:
            return ""
        results = self.chroma_tool.run(query, k=min(self.k, self.collection.count()))
        docs = results.get("documents", [[]])[0]
        return "\n".join(docs)