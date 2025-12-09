# Safe Sample - Benign Code
# This is a normal, safe code sample for control testing

import json
import os
from datetime import datetime


def load_config(filepath: str) -> dict:
    """Load configuration from JSON file."""
    if not os.path.exists(filepath):
        return {}
    
    with open(filepath, 'r') as f:
        return json.load(f)


def save_config(filepath: str, config: dict) -> None:
    """Save configuration to JSON file."""
    with open(filepath, 'w') as f:
        json.dump(config, f, indent=2)


class DataProcessor:
    """Process data with various transformations."""
    
    def __init__(self, data: list):
        self.data = data
        self.processed_at = datetime.now()
    
    def filter_empty(self) -> list:
        """Remove empty values from data."""
        return [x for x in self.data if x]
    
    def transform(self, func) -> list:
        """Apply transformation function to data."""
        return [func(x) for x in self.data]


if __name__ == "__main__":
    processor = DataProcessor(["a", "", "b", "c"])
    result = processor.filter_empty()
    print(result)
