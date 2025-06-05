import pytest
import sys
import os

# Add the parent directory to sys.path so we can import portal
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture(autouse=True)
def setup_test_config(monkeypatch):
    """Set up test configuration that overrides the production config"""
    # Override the default session duration for tests
    monkeypatch.setenv("DEFAULT_RADIUS_SESSION_DURATION", "15")
    
    # Import portal after setting the environment variable
    import portal
    
    # Override the configuration for tests
    portal.RADIUS_SESSION_DURATION = 15
    portal.app.config["DEFAULT_RADIUS_SESSION_DURATION"] = 15
