import math
from collections import Counter

def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0

    frequencies = Counter(text)
    length = len(text)
    entropy = 0.0

    for count in frequencies.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy

def is_high_entropy(text: str, threshold: float = 3.5) -> bool:
    return calculate_entropy(text) > threshold

BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
HEX_CHARS = "0123456789abcdefABCDEF"

def is_high_entropy_string(word: str, min_length: int = 20) -> bool:
    if len(word) < min_length:
        return False

    is_base64 = all(c in BASE64_CHARS for c in word)
    is_hex = all(c in HEX_CHARS for c in word)

    if not (is_base64 or is_hex):
        return False

    return is_high_entropy(word, threshold=3.5)