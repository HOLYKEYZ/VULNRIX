# AI-Generated Malware Pattern Samples

This folder contains test samples for the AI malicious code detection module.

## Files

- `reverse_shell_sample.py` - Example AI-generated reverse shell
- `keylogger_sample.py` - Example AI-generated keylogger
- `token_stealer_sample.py` - Example AI-generated credential stealer
- `obfuscated_sample.py` - Example obfuscated malicious code
- `safe_sample.py` - Benign code (control sample)

## Usage

These samples are used to test and validate the AIMaliciousDetector module.

```python
from vuln_scan.engine.ai_malicious_detection import AIMaliciousDetector

detector = AIMaliciousDetector()
with open('ai_patterns/reverse_shell_sample.py') as f:
    result = detector.run_full_ai_malicious_scan(f.read())
print(result['risk_level'])
```
