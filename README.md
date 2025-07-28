# Advanced Password Strength Checker

Professional security validation tool that analyzes password strength using industry-standard metrics and breach database integration. Built to demonstrate cybersecurity fundamentals and secure coding practices.

## Features
- **Entropy calculation** - Mathematical analysis of password complexity
- **Breach database integration** - HaveIBeenPwned API for compromise detection
- **Pattern recognition** - Detects keyboard patterns, substitutions, and common weaknesses
- **Crack time estimation** - Realistic time-to-crack calculations
- **Security recommendations** - Actionable guidance for improvement
- **Batch analysis** - Multiple password assessment capability

## Technical Skills Demonstrated
- Cryptographic principles and entropy calculation
- API integration and error handling
- Regular expressions for pattern matching
- Mathematical modeling for security analysis
- Professional CLI development
- Data validation and sanitization

## Usage
```bash
# Interactive analysis
python password_checker.py

# Direct password check
python password_checker.py "MyPassword123!"

# Generate secure password
python password_checker.py -g 16

# Batch analysis from file
python password_checker.py -f passwords.txt
