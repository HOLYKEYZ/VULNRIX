# Obfuscated Malicious Code Sample
# Test sample for obfuscation detection

import base64

# Base64 encoded execution
encoded_payload = "cHJpbnQoJ2hlbGxvJyk="
exec(base64.b64decode(encoded_payload))

# High entropy string (obfuscated data)
_0o0O0oO = "aGVsbG9fd29ybGQ=QmFzZTY0RW5jb2RlZFN0cmluZ1RoYXRJc1ZlcnlMb25nQW5kQ29tcGxleA=="

# Character code obfuscation
secret = chr(104) + chr(101) + chr(108) + chr(108) + chr(111)

# Hex encoded string
hex_data = bytes.fromhex("48656c6c6f576f726c6448656c6c6f576f726c64")

# Lambda chain obfuscation
result = (lambda x: (lambda y: y * 2)(x + 1))(5)

# Variable name obfuscation
___oO0 = "payload"
__l1I1l = "data"
oOO0o0O = lambda x: x[::-1]
