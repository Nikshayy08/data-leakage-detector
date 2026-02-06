# ----------- Imports -----------

# Random Forest model (better for non-linear classification)
from sklearn.ensemble import RandomForestClassifier

# Used to save and load trained models
import joblib

# Used to handle file paths safely
from pathlib import Path

# Used to read packets from PCAP files
from scapy.all import rdpcap

# Regular expressions for labeling logic
import re

# Convert text to numerical features
from sklearn.feature_extraction.text import TfidfVectorizer

# Split dataset into train and test
from sklearn.model_selection import train_test_split

# Print evaluation metrics
from sklearn.metrics import classification_report


# ----------- Regex Rules (Day 2 logic reused) -----------

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\b\d{10}\b"
PASSWORD_REGEX = r"(password|pwd|pass)\s*=?\s*\S+"
TOKEN_REGEX = r"(token|api_key|access_key)\s*=?\s*\S+"


def label_payload(text):
    """
    Labels a payload as:
    - High-Risk (passwords or tokens)
    - Suspicious (email or phone)
    - Safe (no sensitive data)
    """

    if re.search(PASSWORD_REGEX, text, re.IGNORECASE) or \
       re.search(TOKEN_REGEX, text, re.IGNORECASE):
        return "High-Risk"

    if re.search(EMAIL_REGEX, text) or \
       re.search(PHONE_REGEX, text):
        return "Suspicious"

    return "Safe"


# ----------- Packet Extraction (Day 1 reused) -----------

def extract_payloads(pcap_path):
    """
    Reads PCAP file and extracts readable payload text
    from packets that contain a Raw layer.
    """

    packets = rdpcap(str(pcap_path))
    payloads = []

    for pkt in packets:
        if pkt.haslayer("Raw"):
            text = pkt["Raw"].load.decode(errors="ignore").strip()
            if text:
                payloads.append(text)

    return payloads


# ----------- MAIN ML PIPELINE -----------

if __name__ == "__main__":

    # Correct path (since we run from project root)
    pcap_path = Path("data/raw_pcaps/sample.pcap")

    # Step 1: Extract payloads
    payloads = extract_payloads(pcap_path)

    # Step 2: Label them using regex rules
    labels = [label_payload(p) for p in payloads]

    # Step 3: Convert text to numerical features (TF-IDF)
    vectorizer = TfidfVectorizer(max_features=500)
    X = vectorizer.fit_transform(payloads)
    y = labels

    # Step 4: Split dataset
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # ----------- Model Training -----------

    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42
    )

    model.fit(X_train, y_train)

    # ----------- Evaluation -----------

    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))

    # ----------- Save Model & Vectorizer -----------

    joblib.dump(model, "models/model.pkl")
    joblib.dump(vectorizer, "models/vectorizer.pkl")

    print("Model and vectorizer saved successfully.")
