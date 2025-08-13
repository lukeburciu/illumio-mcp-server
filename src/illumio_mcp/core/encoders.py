"""Custom JSON encoders for Illumio objects"""
from json import JSONEncoder

class IllumioJSONEncoder(JSONEncoder):
    """Custom JSON encoder for Illumio SDK objects"""
    def default(self, obj):
        if hasattr(obj, '__dict__'):
            return obj.__dict__
        elif isinstance(obj, list):
            return [self.default(item) for item in obj]
        elif isinstance(obj, dict):
            return {key: self.default(value) for key, value in obj.items()}
        else:
            return super().default(obj)