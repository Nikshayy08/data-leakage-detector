# Used to handle file paths safely (OS-independent)
from pathlib import Path

# rdpcap reads packets from a PCAP file
from scapy.all import rdpcap

# Regular expressions for pattern matching
import re

# Machine Learning libraries
from sklearn.feature_extraction.text import TfidfVectorizer   # Text → numerical features
from sklearn.linear_model import LogisticRegression           # ML classification model
from sklearn.model_selection import train_test_split          # Split data into train/test
from sklearn.metrics import classification_report             # Model evaluation metrics


# ---------- Regex rules (from Day 2) ----------
# These patterns are used to label payloads automatically

EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
PHONE_REGEX = r"\b\d{10}\b"
PASSWORD_REGEX = r"(password|pwd|pass)\s*=?\s*\S+"
TOKEN_REGEX = r"(token|api_key|access_key)\s*=?\s*\S+"


def label_payload(text):
    """
    Assigns a risk label to a given text payload using regex rules.

    Returns:
        High-Risk    -> passwords or tokens
        Suspicious   -> emails or phone numbers
        Safe         -> no sensitive data
    """

    # Check for highly sensitive information
    if re.search(PASSWORD_REGEX, text, re.IGNORECASE) or \
       re.search(TOKEN_REGEX, text, re.IGNORECASE):
        return "High-Risk"

    # Check for personal information
    if re.search(EMAIL_REGEX, text) or \
       re.search(PHONE_REGEX, text):
        return "Suspicious"

    # If no sensitive pattern is found
    return "Safe"


# ---------- Packet Extraction (from Day 1) ----------
def extract_payloads(pcap_path):
    """
    Reads a PCAP file and extracts readable payload text
    from packets containing a Raw layer.
    """

    # Load all packets from the PCAP file
    packets = rdpcap(str(pcap_path))
    payloads = []

    # Iterate through each packet
    for pkt in packets:
        # Check if packet contains actual payload
        if pkt.haslayer("Raw"):
            # Decode payload bytes into readable text
            text = pkt["Raw"].load.decode(errors="ignore").strip()

            # Store only non-empty payloads
            if text:
                payloads.append(text)

    return payloads


# ---------- MAIN PIPELINE ----------
if __name__ == "__main__":

    # Path to the PCAP file
    pcap_path = Path("../data/raw_pcaps/sample.pcap")

    # Step 1: Extract payloads from network packets
    payloads = extract_payloads(pcap_path)

    # Step 2: Automatically label payloads using regex rules
    labels = [label_payload(p) for p in payloads]

    # Step 3: Convert text payloads into numerical features (TF-IDF)
    vectorizer = TfidfVectorizer(max_features=500)
    X = vectorizer.fit_transform(payloads)
    y = labels

    # Step 4: Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42
    )

    # Step 5: Train the ML model
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    # Step 6: Test and evaluate the model
    y_pred = model.predict(X_test)
    print(classification_report(y_test, y_pred))
