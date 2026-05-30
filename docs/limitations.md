## Documented False Positives

### BASE64_CHARS and HEX_CHARS — entropy.py (resolved)

What I Detected: 
    High Entropy String on lines 21 and 22 of core/entropy.py
Why it fired: 
    The character set definitions for BASE64_CHARS and HEX_CHARS contain every letter and digit — mathematically identical to a high entropy secret string.
Why it matters: 
    This is a textbook example of why entropy analysis alone is not sufficient. A string can look like a secret mathematically without being one contextually.
Resolution: 
    Added IGNORED_LINES to the scanner to skip lines containing known character set definitions.
Lesson:
    Every entropy-based scanner in production(including truffleHog and GitGuardian) maintains an allowlist of known false positive patterns. This is an ongoing process, not a one-time fix.