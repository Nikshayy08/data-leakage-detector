# Import rdpcap from scapy
# rdpcap is used to READ packets from a .pcap file
from scapy.all import rdpcap

# Path helps in handling file paths in a clean, OS-independent way
from pathlib import Path


# Path to the PCAP file
# ".." means go one directory up (project root)
# then move into data/raw_pcaps/sample.pcap
PCAP_PATH = Path("../data/raw_pcaps/sample.pcap")


def extract_payloads(pcap_path):
    """
    This function reads a PCAP file and extracts readable payload data
    from packets that contain actual content (Raw layer).

    Input:
        pcap_path -> path to the .pcap file

    Output:
        payloads -> list of extracted payload strings
    """

    # Read all packets from the PCAP file
    # rdpcap returns a list-like object of packets
    packets = rdpcap(str(pcap_path))

    # Empty list to store extracted payload text
    payloads = []

    # Loop through each packet one by one
    for pkt in packets:

        # Check if the packet contains a Raw layer
        # Raw layer usually contains the actual payload/data
        if pkt.haslayer("Raw"):

            # Extract raw payload data (in bytes)
            raw_data = pkt["Raw"].load

            # Convert bytes to readable text
            # errors="ignore" skips unreadable characters safely
            # strip() removes extra spaces and new lines
            text = raw_data.decode(errors="ignore").strip()

            # Store only non-empty payloads
            if text:
                payloads.append(text)

    # Return all extracted payloads
    return payloads


# This block ensures the code runs only when
# this file is executed directly (not imported)
if __name__ == "__main__":

    # Call the payload extraction function
    payloads = extract_payloads(PCAP_PATH)

    # Print total number of extracted payloads
    print(f"Extracted {len(payloads)} payloads\n")

    # Print only the first 10 payloads for inspection
    # enumerate(..., 1) starts numbering from 1
    for i, p in enumerate(payloads[:10], 1):
        print(f"{i}. {p}")
