# Import the regular expression module
# It is used to search for specific patterns in text
import re 


# Regex pattern to detect email addresses
# Example: abc@gmail.com
EMAIL_REGEX = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"


# Regex pattern to detect 10-digit phone numbers
# Example: 9876543210
PHONE_REGEX = r"\b\d{10}\b"


# Regex pattern to detect password-related data
# Looks for words like password, pwd, pass followed by a value
# Example: password=hello123
PASSWORD_REGEX = r"(password|pwd|pass)\s*=?\s*\S+"


# Regex pattern to detect tokens or API keys
# These are highly sensitive credentials
# Example: token=abcd1234
TOKEN_REGEX = r"(token|api_key|access_key)\s*=?\s*\S+"


def detect_sensitive_data(text):
    """
    This function analyzes a given text and classifies it as:
    - High-Risk: contains passwords or tokens
    - Suspicious: contains email or phone number
    - Safe: contains no sensitive information
    """

    # Check for highly sensitive data first (passwords or tokens)
    # re.IGNORECASE allows matching regardless of uppercase/lowercase
    if re.search(PASSWORD_REGEX, text, re.IGNORECASE) or \
       re.search(TOKEN_REGEX, text, re.IGNORECASE):
        return "High-Risk"

    # Check for personal information (email or phone number)
    if re.search(EMAIL_REGEX, text) or \
       re.search(PHONE_REGEX, text):
        return "Suspicious"

    # If no sensitive patterns are found, mark data as safe
    return "Safe"


# This block runs only when this file is executed directly
# It is used here to test the detection logic
if __name__ == "__main__":

    # Sample text inputs to test the function
    samples = [
        "hello welcome to homepage",
        "email=abc@gmail.com",
        "password=hello123",
        "token=skdjf9834ksd",
        "phone=9876543210"
    ]

    # Loop through each sample text
    # Print the text along with its detected risk level
    for s in samples:
        print(s, "→", detect_sensitive_data(s))
