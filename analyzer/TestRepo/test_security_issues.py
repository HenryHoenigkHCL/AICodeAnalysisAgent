"""
Additional test module with security issues and more violations.
Used to test the PostBuild Code Analysis Agent detection capabilities.
"""

import os
import subprocess
from typing import List, Dict, Optional
import pickle
import sqlite3


# Global variable with bad naming
GLOBAL_SECURITY_TOKEN = "sk_live_abc123def456xyz789"


class SQLInjectionExample:
    """Class with potential SQL injection vulnerability."""

    def __init__(self, db_path: str):
        self.connection = sqlite3.connect(db_path)

    def QueryUser(self, user_id: str) -> Dict:
        """Bad naming: should be query_user."""
        # SQL Injection vulnerability - user_id is not parameterized
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor = self.connection.cursor()
        cursor.execute(query)
        
        result = cursor.fetchone()
        # Null dereference if result is None
        return {"id": result[0], "name": result[1]}

    def UpdateUserPassword(self, user_id: str, password: str):
        """Bad naming: should be update_user_password."""
        # Another SQL injection - no parameterization
        query = f"UPDATE users SET password = '{password}' WHERE id = {user_id}"
        cursor = self.connection.cursor()
        cursor.execute(query)
        self.connection.commit()


class CommandExecutionRisk:
    """Class with command execution vulnerability."""

    def execute_command(self, user_command: str) -> str:
        """
        This function is very long and has multiple issues including:
        - Command injection vulnerability
        - Missing input validation
        - Excessive nesting
        - Poor error handling
        """
        if user_command:
            if len(user_command) > 0:
                if user_command.strip():
                    # Command injection - user_command not sanitized
                    result = subprocess.run(
                        f"bash -c '{user_command}'",
                        shell=True,
                        capture_output=True,
                        timeout=30
                    )
                    
                    if result.returncode == 0:
                        output = result.stdout.decode()
                        
                        if output:
                            if len(output) > 100:
                                output = output[:100] + "..."
                            
                            return output
                        else:
                            return "No output"
                    else:
                        error = result.stderr.decode()
                        if error:
                            return f"Error: {error}"
                        else:
                            return "Unknown error"
        
        return None


class InsecurePickling:
    """Insecure deserialization with pickle."""

    def LoadData(self, file_path: str):
        """Bad naming: should be load_data."""
        # Dangerous - pickle.load() can execute arbitrary code
        with open(file_path, "rb") as f:
            data = pickle.load(f)
        
        return data

    def SaveData(self, data: object, file_path: str):
        """Bad naming: should be save_data."""
        with open(file_path, "wb") as f:
            pickle.dump(data, f)


class HardcodedCredentials:
    """Class with hardcoded secrets - MAJOR security issue."""

    # Hardcoded credentials - security vulnerability
    API_KEY = "sk_test_51234567890abcdefghijklmno"
    DATABASE_PASSWORD = "admin123"
    AWS_SECRET = "AKIAIOSFODNN7EXAMPLE"
    
    def __init__(self):
        self.api_token = "bearer_token_12345"
        self.db_password = "postgres_password"

    def authenticate(self, user_creds: Optional[Dict] = None):
        # No docstring
        # Missing null check
        username = user_creds["username"]
        password = user_creds["password"]
        
        # Comparing with hardcoded password - bad practice
        if password == self.DATABASE_PASSWORD:
            return True
        
        return False


class BadErrorHandling:
    """Class with poor error handling practices."""

    def process_file(self, file_path: str):
        """
        Process a file with poor error handling.
        This function violates multiple standards.
        """
        # Bare except catches everything including SystemExit, KeyboardInterrupt
        try:
            with open(file_path, "r") as f:
                content = f.read()
            
            lines = content.split("\n")
            
            if lines:
                if len(lines) > 0:
                    for line in lines:
                        if line.strip():
                            # Risky operation with no error handling
                            parts = line.split("|")
                            value = int(parts[0])
                            return value
        except:
            # Bad practice: bare except
            pass
        
        return None

    def validate_and_process(self, DATA):
        # Bad naming: DATA should be data
        # No docstring
        # Missing null checks
        try:
            parsed = eval(DATA)
            return parsed
        except Exception as e:
            # Logging exception details could leak sensitive info
            print(f"Error: {e}")
            return None


class WeakCryption:
    """Uses weak or incorrect cryptography."""

    def encrypt_data(self, data: str) -> str:
        """
        Encrypt data with weak algorithm.
        Very long function with multiple issues.
        """
        import hashlib
        
        if data:
            if len(data) > 0:
                # Using MD5 for encryption - major security flaw
                # MD5 is cryptographically broken
                hash_obj = hashlib.md5()
                hash_obj.update(data.encode())
                hashed = hash_obj.hexdigest()
                
                if hashed:
                    if len(hashed) > 10:
                        # Attempting to use hash as encryption - insecure
                        encrypted = hashed
                        
                        if encrypted:
                            return encrypted
        
        return None

    def BadlyNamedDecrypt(self, encrypted: str) -> str:
        """Bad naming: should be badly_named_decrypt or decrypt_data."""
        # Can't decrypt MD5 hash - fundamental flaw
        # Null dereference risk
        return encrypted.upper()


class MissingValidation:
    """Missing input validation throughout."""

    def process_user_input(self, user_data):
        # No docstring
        # No type hints
        # No validation
        # Multiple null dereferences
        name = user_data["name"]
        age = user_data["age"]
        email = user_data["email"]
        
        if age < 0:
            return False
        
        if age > 150:
            return False
        
        # Null dereference - no check if email is None
        if "@" not in email:
            return False
        
        # Multiple unsafe operations
        name_upper = name.upper()
        email_lower = email.lower()
        
        # Another null dereference - no check on split result
        domain = email_lower.split("@")[1]
        
        return {
            "name": name_upper,
            "age": age,
            "email": email_lower,
            "domain": domain
        }


class RaceCondition:
    """Example with potential race condition."""

    def __init__(self):
        self.file_path = "/tmp/shared_resource.txt"

    def unsafe_file_operation(self, data: str):
        """
        Unsafe file operation that can lead to race conditions.
        """
        # Check if file exists
        if os.path.exists(self.file_path):
            # FILE COULD BE DELETED HERE BY ANOTHER PROCESS
            # Time-of-check-time-of-use (TOCTTOU) vulnerability
            with open(self.file_path, "r") as f:
                existing = f.read()
        else:
            existing = ""
        
        # Write data (overwrites without proper locking)
        with open(self.file_path, "w") as f:
            f.write(existing + data)

    def read_file(self):
        # No docstring
        # Null dereference if file doesn't exist
        with open(self.file_path, "r") as f:
            return f.read()
