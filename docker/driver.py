from neo4j import GraphDatabase
import chromadb

# Neo4j
driver = GraphDatabase.driver("bolt://neo4j:7687", auth=("neo4j", "testpassword"))

# Chroma
client = chromadb.HttpClient(host="chroma", port=8000)