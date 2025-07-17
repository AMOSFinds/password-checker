#!/usr/bin/env python3
"""
Advanced Password Strength Checker - Professional Security Validation Tool
Author: Amos Mashele
Description: Comprehensive password analysis with security recommendations
"""

import re
import math
import argparse
import hashlib
import requests
import json
import time
from datetime import datetime
from colorama import init, Fore, Style
import string
import secrets


init()

class PasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.keyboard_patterns = [
            'qwerty', 'asdf', 'zxcv', '1234', 'abcd', 'qwer',
            'asdfgh', 'zxcvbn', '123456', 'password', 'admin'
        ]
        self.personal_info_patterns = [
            'name', 'birthday', 'address', 'phone', 'email',
            'username', 'company', 'pet', 'spouse', 'child'
        ]
        
    def load_common_passwords(self):
        """Load common passwords for checking"""
        common_passwords = [
            'password', '123456', 'password123', 'admin', 'qwerty',
            'letmein', 'welcome', 'monkey', '1234567890', 'password1',
            'abc123', '123456789', 'welcome123', 'admin123', 'root',
            'toor', 'pass', 'test', 'guest', 'user', 'login',
            'changeme', 'newpassword', 'secret', 'god', 'love',
            'sex', 'money', 'home', 'work', 'computer', 'internet'
        ]
        return set(common_passwords)
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗
║                                        PASSWORD STRENGTH CHECKER                                                    ║
║                                     Professional Security Validation                                                ║
╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
"""
        print(banner)
    
    def calculate_entropy(self, password):
        """Calculate password entropy"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += len(string.punctuation)
        
        if charset_size == 0:
            return 0
        
        entropy = len(password) * math.log2(charset_size)
        return entropy
    
    def check_character_variety(self, password):
        """Check character variety in password"""
        checks = {
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'digits': any(c.isdigit() for c in password),
            'special': any(c in string.punctuation for c in password),
            'length': len(password) >= 8
        }
        return checks
    
    def check_common_patterns(self, password):
        """Check for common password patterns"""
        patterns = []
        password_lower = password.lower()
        
        # Check for keyboard patterns
        for pattern in self.keyboard_patterns:
            if pattern in password_lower:
                patterns.append(f"Keyboard pattern: {pattern}")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            patterns.append("Repeated characters detected")
        
        # Check for sequential numbers
        if re.search(r'01234|12345|23456|34567|45678|56789', password):
            patterns.append("Sequential numbers detected")
        
        # Check for sequential letters
        if re.search(r'abcd|bcde|cdef|defg|efgh|fghi|ghij', password_lower):
            patterns.append("Sequential letters detected")
        
        # Check for common substitutions
        substitutions = {
            '@': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's',
            '7': 't', '4': 'a', '8': 'b', '6': 'g', '2': 'z'
        }
        
        desubstituted = password_lower
        for num, letter in substitutions.items():
            desubstituted = desubstituted.replace(num, letter)
        
        if desubstituted in self.common_passwords:
            patterns.append("Common password with character substitution")
        
        return patterns
    
    def check_common_passwords(self, password):
        """Check against common password lists"""
        if password.lower() in self.common_passwords:
            return True
        return False
    
    def check_pwned_passwords(self, password):
        """Check if password appears in data breaches using HaveIBeenPwned API"""
        try:
            # Hash the password
            sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
            prefix = sha1_hash[:5]
            suffix = sha1_hash[5:]
            
            # Query the API
            url = f"https://api.pwnedpasswords.com/range/{prefix}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                hashes = response.text.split('\n')
                for hash_line in hashes:
                    if ':' in hash_line:
                        hash_suffix, count = hash_line.split(':')
                        if hash_suffix == suffix:
                            return int(count)
            return 0
        except:
            return -1  # API unavailable
    
    def estimate_crack_time(self, password):
        """Estimate time to crack password"""
        charset_size = 0
        
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in string.punctuation for c in password):
            charset_size += len(string.punctuation)
        
        if charset_size == 0:
            return "Cannot estimate"
        
        total_combinations = charset_size ** len(password)
        # Assume 1 billion attempts per second
        attempts_per_second = 1_000_000_000
        
        # Average time to crack (half of total combinations)
        seconds_to_crack = total_combinations / (2 * attempts_per_second)
        
        return self.format_time(seconds_to_crack)
    
    def format_time(self, seconds):
        """Format time in human-readable format"""
        if seconds < 1:
            return "Less than 1 second"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        else:
            return f"{seconds/31536000:.1f} years"
    
    def get_strength_score(self, password):
        """Calculate overall password strength score"""
        score = 0
        
        # Length scoring
        length = len(password)
        if length >= 8:
            score += 2
        if length >= 12:
            score += 2
        if length >= 16:
            score += 2
        
        # Character variety
        checks = self.check_character_variety(password)
        score += sum(checks.values())
        
        # Entropy scoring
        entropy = self.calculate_entropy(password)
        if entropy >= 40:
            score += 2
        if entropy >= 60:
            score += 2
        
        # Penalty for common patterns
        patterns = self.check_common_patterns(password)
        score -= len(patterns)
        
        # Penalty for common passwords
        if self.check_common_passwords(password):
            score -= 5
        
        # Penalty for pwned passwords
        pwned_count = self.check_pwned_passwords(password)
        if pwned_count > 0:
            score -= 3
        
        return max(0, min(10, score))
    
    def get_strength_level(self, score):
        """Get strength level based on score"""
        if score <= 2:
            return "Very Weak", Fore.RED
        elif score <= 4:
            return "Weak", Fore.YELLOW
        elif score <= 6:
            return "Fair", Fore.YELLOW
        elif score <= 8:
            return "Good", Fore.GREEN
        else:
            return "Excellent", Fore.GREEN
    
    def generate_recommendations(self, password, checks, patterns):
        """Generate security recommendations"""
        recommendations = []
        
        if len(password) < 8:
            recommendations.append("Use at least 8 characters (12+ recommended)")
        
        if not checks['lowercase']:
            recommendations.append("Include lowercase letters")
        
        if not checks['uppercase']:
            recommendations.append("Include uppercase letters")
        
        if not checks['digits']:
            recommendations.append("Include numbers")
        
        if not checks['special']:
            recommendations.append("Include special characters (!@#$%^&*)")
        
        if patterns:
            recommendations.append("Avoid common patterns and keyboard sequences")
        
        if self.check_common_passwords(password):
            recommendations.append("Avoid common passwords")
        
        recommendations.append("Use a unique password for each account")
        recommendations.append("Consider using a password manager")
        
        return recommendations
    
    def analyze_password(self, password):
        """Perform comprehensive password analysis"""
        print(f"\n{Fore.CYAN}Analyzing password...{Style.RESET_ALL}")
        
        # Basic checks
        length = len(password)
        entropy = self.calculate_entropy(password)
        checks = self.check_character_variety(password)
        patterns = self.check_common_patterns(password)
        is_common = self.check_common_passwords(password)
        
        # Advanced checks
        print(f"{Fore.YELLOW}Checking against breach databases...{Style.RESET_ALL}")
        pwned_count = self.check_pwned_passwords(password)
        
        crack_time = self.estimate_crack_time(password)
        score = self.get_strength_score(password)
        strength_level, color = self.get_strength_level(score)
        
        # Display results
        print(f"\n{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗")
        print(f"║                                            ANALYSIS RESULTS                                                        ║")
        print(f"╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}Password Length:{Style.RESET_ALL} {length} characters")
        print(f"{Fore.YELLOW}Entropy:{Style.RESET_ALL} {entropy:.1f} bits")
        print(f"{Fore.YELLOW}Estimated Crack Time:{Style.RESET_ALL} {crack_time}")
        print(f"{Fore.YELLOW}Strength Score:{Style.RESET_ALL} {score}/10")
        print(f"{Fore.YELLOW}Strength Level:{Style.RESET_ALL} {color}{strength_level}{Style.RESET_ALL}")
        
        # Character variety
        print(f"\n{Fore.CYAN}CHARACTER VARIETY:{Style.RESET_ALL}")
        for check, passed in checks.items():
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if passed else f"{Fore.RED}✗{Style.RESET_ALL}"
            print(f"  {status} {check.capitalize()}")
        
        # Security issues
        if patterns or is_common or pwned_count > 0:
            print(f"\n{Fore.RED}SECURITY ISSUES:{Style.RESET_ALL}")
            
            if is_common:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Common password detected")
            
            if pwned_count > 0:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} Found in {pwned_count:,} data breaches")
            elif pwned_count == -1:
                print(f"  {Fore.YELLOW}!{Style.RESET_ALL} Could not check breach databases")
            
            for pattern in patterns:
                print(f"  {Fore.RED}✗{Style.RESET_ALL} {pattern}")
        
        # Recommendations
        recommendations = self.generate_recommendations(password, checks, patterns)
        if recommendations:
            print(f"\n{Fore.CYAN}RECOMMENDATIONS:{Style.RESET_ALL}")
            for i, rec in enumerate(recommendations, 1):
                print(f"  {i}. {rec}")
        
        return {
            'length': length,
            'entropy': entropy,
            'score': score,
            'strength_level': strength_level,
            'pwned_count': pwned_count,
            'patterns': patterns,
            'recommendations': recommendations
        }
    
    def generate_secure_password(self, length=16, include_symbols=True):
        """Generate a secure password"""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += "!@#$%^&*"
        
        password = ''.join(secrets.choice(characters) for _ in range(length))
        return password
    
    def batch_analysis(self, passwords):
        """Analyze multiple passwords"""
        results = []
        
        print(f"\n{Fore.CYAN}Analyzing {len(passwords)} passwords...{Style.RESET_ALL}")
        
        for i, password in enumerate(passwords, 1):
            print(f"\n{Fore.YELLOW}Password {i}:{Style.RESET_ALL}")
            result = self.analyze_password(password)
            results.append(result)
            
            if i < len(passwords):
                print(f"\n{'-' * 80}")
        
        return results

def main():
    parser = argparse.ArgumentParser(description='Advanced Password Strength Checker')
    parser.add_argument('password', nargs='?', help='Password to analyze')
    parser.add_argument('-f', '--file', help='File containing passwords to analyze')
    parser.add_argument('-g', '--generate', type=int, help='Generate secure password of specified length')
    parser.add_argument('--batch', action='store_true', help='Batch analysis mode')
    parser.add_argument('--no-breach-check', action='store_true', help='Skip breach database check')
    
    args = parser.parse_args()
    
    checker = PasswordChecker()
    checker.print_banner()
    
    if args.generate:
        print(f"\n{Fore.CYAN}Generated secure password:{Style.RESET_ALL}")
        password = checker.generate_secure_password(args.generate)
        print(f"{Fore.GREEN}{password}{Style.RESET_ALL}")
        
        # Optionally analyze the generated password
        print(f"\n{Fore.CYAN}Analysis of generated password:{Style.RESET_ALL}")
        checker.analyze_password(password)
    
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            checker.batch_analysis(passwords)
        except FileNotFoundError:
            print(f"{Fore.RED}Error: File '{args.file}' not found{Style.RESET_ALL}")
    
    elif args.password:
        checker.analyze_password(args.password)
    
    else:
        # Interactive mode
        print(f"{Fore.CYAN}Enter password to analyze (or 'quit' to exit):{Style.RESET_ALL}")
        while True:
            try:
                password = input(f"{Fore.YELLOW}Password: {Style.RESET_ALL}")
                if password.lower() == 'quit':
                    break
                if password:
                    checker.analyze_password(password)
                    print(f"\n{'-' * 80}")
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}Exiting...{Style.RESET_ALL}")
                break

if __name__ == "__main__":
    main()
