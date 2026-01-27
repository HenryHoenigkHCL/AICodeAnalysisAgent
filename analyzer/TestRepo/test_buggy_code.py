"""
Test module with intentional bugs and coding standard violations.
This is used to test the PostBuild Code Analysis Agent.
"""

from typing import Optional, Dict, Any, List
import json


class DataProcessor:
    """Processes data with intentional null pointer risks."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config
        self.cache = None
        self.results = None

    def ProcessData(self, raw_data: str) -> Dict[str, Any]:
        """Process raw data and return results - BAD NAMING (should be process_data)."""
        # Missing null check - will crash if config is None
        api_key = self.config["api_key"]
        
        parsed = json.loads(raw_data)
        
        # Null pointer dereference - results might be None
        self.results.append(parsed)
        
        return self._NestedProcessing(parsed, api_key)

    def _NestedProcessing(self, data: Dict, key: str) -> Dict[str, Any]:
        """
        This function is way too long and violates the max_function_lines standard.
        It has excessive nesting and multiple responsibilities that should be split.
        """
        # Level 1
        if data:
            if "user" in data:
                if isinstance(data["user"], dict):
                    if "profile" in data["user"]:
                        if "settings" in data["user"]["profile"]:
                            if "preferences" in data["user"]["profile"]["settings"]:
                                if "theme" in data["user"]["profile"]["settings"]["preferences"]:
                                    theme = data["user"]["profile"]["settings"]["preferences"]["theme"]
                                    
                                    # Null dereference
                                    theme_name = theme.lower()
                                    
                                    if theme_name == "dark":
                                        config_data = {
                                            "colors": {"bg": "#000", "fg": "#fff"},
                                            "fonts": {"primary": "Arial", "mono": "Courier"},
                                            "sizes": {"small": 10, "medium": 14, "large": 18},
                                            "spacing": {"xs": 2, "sm": 4, "md": 8, "lg": 16},
                                        }
                                    elif theme_name == "light":
                                        config_data = {
                                            "colors": {"bg": "#fff", "fg": "#000"},
                                            "fonts": {"primary": "Arial", "mono": "Courier"},
                                            "sizes": {"small": 10, "medium": 14, "large": 18},
                                            "spacing": {"xs": 2, "sm": 4, "md": 8, "lg": 16},
                                        }
                                    else:
                                        config_data = {}
                                    
                                    # Null dereference on cache
                                    self.cache["theme"] = theme_name
                                    
                                    return {
                                        "status": "success",
                                        "data": config_data,
                                        "key": key,
                                    }
        
        return {"status": "error", "data": None, "key": key}


class EventHandler:
    """Handles events with poor standards - no docstrings, bad naming."""

    def __init__(self):
        self.handlers = {}
        self.logger = None

    def RegisterHandler(self, EVENT_NAME: str, handler):
        """Register an event handler - bad naming: EVENT_NAME should be event_name."""
        # No null check on logger
        self.logger.info(f"Registering {EVENT_NAME}")
        self.handlers[EVENT_NAME] = handler

    def TriggerEvent(self, evt_name, evt_data):
        # No docstring, bad parameter names, missing None check
        handler = self.handlers.get(evt_name)
        
        # Null dereference
        result = handler(evt_data)
        
        # Null dereference on logger
        self.logger.debug(f"Event triggered: {evt_name}")
        
        return result

    def cleanup(self):
        # No docstring
        # This line will crash if handlers contain None
        for name, handler_func in self.handlers.items():
            handler_func(None)


class _InvalidPrivateClass:
    """Bad naming: private classes should use _name convention - this one has capital letter."""

    def __init__(self, data: Optional[List[str]] = None):
        self.data = data

    def CONSTANT_METHOD(self):
        """Method with constant naming - should be constant_method."""
        # Null pointer dereference
        return len(self.data)

    def BadlyNamedMethod_WithUnderscores(self):
        """Another naming violation."""
        # No null check
        return self.data[0]


class ConfigValidator:
    """Validates config with high cyclomatic complexity."""

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """
        Complex validation function that violates standards:
        - Too long (should be split)
        - Too many nested conditions
        - Missing null checks
        """
        if config is None:
            return False
        
        if "database" not in config:
            return False
        
        db = config["database"]
        if "host" not in db:
            return False
        
        if "port" not in db:
            return False
        
        if "credentials" not in db:
            return False
        
        creds = db["credentials"]
        
        # Null dereference
        username = creds["username"]
        password = creds["password"]
        
        if not username or not password:
            return False
        
        if len(username) < 3:
            return False
        
        if len(password) < 8:
            return False
        
        # More nested validation
        if "ssl" in db:
            ssl_config = db["ssl"]
            if "enabled" in ssl_config:
                if ssl_config["enabled"]:
                    if "cert_path" not in ssl_config:
                        return False
                    
                    cert = ssl_config["cert_path"]
                    if not cert.endswith(".pem"):
                        if not cert.endswith(".crt"):
                            if not cert.endswith(".cert"):
                                return False
        
        # Yet more conditions
        if "pool" in db:
            pool = db["pool"]
            if "min_size" in pool and "max_size" in pool:
                # Null dereference
                if pool["min_size"] > pool["max_size"]:
                    return False
        
        return True


class DataCache:
    """Cache with potential null pointer issues."""

    def __init__(self, max_size: int = 100):
        self.max_size = max_size
        self.data = {}
        self.access_count = None

    def SET_VALUE(self, key: str, value: Any):
        """Bad naming - should be set_value (snake_case)."""
        # Null dereference on access_count
        self.access_count[key] += 1
        
        if len(self.data) >= self.max_size:
            # Evict oldest
            oldest = min(self.data.keys(), key=lambda k: self.access_count[k])
            del self.data[oldest]
            del self.access_count[oldest]
        
        self.data[key] = value

    def GET_VALUE(self, key: str):
        """Bad naming - should be get_value (snake_case)."""
        # Potential null dereference
        self.access_count[key] += 1
        return self.data.get(key)

    def ClearCache(self):
        # Bad naming - should be clear_cache
        # No docstring
        # Null dereference if data is None
        for key in self.data.keys():
            del self.data[key]
            del self.access_count[key]
