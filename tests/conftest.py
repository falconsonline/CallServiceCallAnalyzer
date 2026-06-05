import importlib.util
import sys
import os
import warnings

_spec = importlib.util.spec_from_file_location(
    "extract_callservice_logs",
    os.path.join(os.path.dirname(__file__), '..', 'extract-callservice-logs.py')
)
_module = importlib.util.module_from_spec(_spec)
sys.modules['extract_callservice_logs'] = _module
try:
    _spec.loader.exec_module(_module)
except Exception as e:
    warnings.warn(f"Could not fully load extract_callservice_logs: {e}")
