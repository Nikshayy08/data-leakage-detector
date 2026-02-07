# -------------------- Imports --------------------

# Used to load saved ML model and vectorizer
import joblib

# Used to handle file paths safely
from pathlib import Path

# Used to read packets from PCAP file
from scapy.all import rdpcap

# Import RAG explanation function
from rag_engine import explain


# -------------------- File Paths --------------------

# Path to saved trained ML model
MODEL_PATH = Path("models/model.pkl")

# Path to saved TF-IDF vectorizer
VECTORIZER_PATH = Path("models/vectorizer.pkl")

# Path to PCAP file to analyze
PCAP_PATH = Path("data/raw_pcaps/sample.pcap")


# -------------------- Packet Extraction --------------------

def extract_payloads(pcap_path):
    """
    Reads a PCAP file and extracts readable payload text
    from packets containing a Raw layer.
    """

    packets = rdpcap(str(pcap_path))
    payloads = []

    for pkt in packets:
        # Check if packet contains actual payload data
        if pkt.haslayer("Raw"):
            text = pkt["Raw"].load.decode(errors="ignore").strip()

            # Store only non-empty payloads
            if text:
                payloads.append(text)

    return payloads


# -------------------- Prediction + RAG Layer --------------------

if __name__ == "__main__":

    # Load trained ML model
    model = joblib.load(MODEL_PATH)

    # Load trained TF-IDF vectorizer
    vectorizer = joblib.load(VECTORIZER_PATH)

    # Extract payloads from PCAP
    payloads = extract_payloads(PCAP_PATH)

    # If no payloads found
    if not payloads:
        print("No payloads found in PCAP file.")
        exit()

    # Convert payload text into numerical features
    # IMPORTANT: use transform() (not fit_transform)
    X = vectorizer.transform(payloads)

    # Predict risk labels
    predictions = model.predict(X)

    # Display results
    for payload, risk in zip(payloads, predictions):

        print("\n----------------------------------------")
        print(f"[Prediction: {risk}]")
        print(f"Payload: {payload[:120]}")

        # If payload is risky, use RAG to explain
        if risk != "Safe":
            explanation = explain(payload)
            print("\nExplanation:")
            print(explanation)

    print("\nAnalysis complete.")
