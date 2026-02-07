from sentence_transformers import SentenceTransformer
import faiss
import os
from pathlib import Path

# Path to knowledge directory
KNOWLEDGE_PATH = Path("knowledge")

# Load embedding model
model = SentenceTransformer("all-MiniLM-L6-v2")

# Load documents
documents = []
doc_names = []

for file in os.listdir(KNOWLEDGE_PATH):
    file_path = KNOWLEDGE_PATH / file
    with open(file_path, "r", encoding="utf-8") as f:
        documents.append(f.read())
        doc_names.append(file)

# Convert documents to embeddings
embeddings = model.encode(documents)

# Build FAISS index
dimension = embeddings.shape[1]
index = faiss.IndexFlatL2(dimension)
index.add(embeddings)


def explain(payload_text):
    """
    Returns most relevant security explanation
    for a given payload.
    """

    query_embedding = model.encode([payload_text])
    distances, indices = index.search(query_embedding, k=1)

    return documents[indices[0][0]]
