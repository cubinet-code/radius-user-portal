import pytest
from portal import app
from flask import session
import time
import re


@pytest.fixture()
def application():
    return app


@pytest.fixture()
def client():
    return app.test_client()


def test_app_config(application):
    assert application.config.get("SECRET_KEY") is not None
    assert application.config.get("RADIUS_SERVER") is not None
    assert application.config.get("RADIUS_SECRET") is not None


def test_login_empty_password(client):
    response = client.post(
        "/",
        data={
            "username": "testuser",
            "password": "",
            "login": "",
        },
    )
    assert b"password: This field is required" in response.data


def test_login_wrong_password(client):
    response = client.post(
        "/",
        data={
            "username": "testuser",
            "password": "TEST",
            "login": "",
        },
    )
    assert b"Unknown user or incorrect password" in response.data


def test_login_success(client):
    response = client.post(
        "/",
        data={
            "username": "testuser",
            "password": "d5GyvkSV",
            "login": "",
        },
    )
    assert b"Successfully logged in" in response.data


def test_portal_session(client):
    with client:
        # Login
        client.post(
            "/",
            data={
                "username": "testuser",
                "password": "d5GyvkSV",
                "login": "",
            },
        )

        assert session["username"] == "testuser"
        assert session["ip"] == "127.0.0.1"
        assert session["id"] != ""
        assert session["duration"] == 15
        assert session["end"] == session["start"] + session["duration"]

        time.sleep(1)
        now = time.time()
        # After sleeping 1 second, there should be ~14 seconds remaining
        remaining_time = session["end"] - now
        # Allow for more tolerance due to processing delays, test duration should be between 9-15 seconds
        assert 9 <= remaining_time <= 15

        # Extend session
        client.post(
            "/",
            data={
                "extend": "",
                "duration": str(session["duration"]),
            },
        )

        assert session["username"] == "testuser"
        assert session["ip"] == "127.0.0.1"
        assert session["id"] != ""
        assert session["end"] == session["start"] + session["duration"]

        # Logout
        client.post(
            "/",
            data={
                "logout": "",
            },
        )

        assert session.get("username") is None


def test_csp_nonce_in_response(client):
    """Test that CSP nonce is present in script tags"""
    response = client.get("/")
    assert response.status_code == 200
    
    # Check that the inline script has a nonce attribute
    assert b'nonce="' in response.data
    assert b'<script type="text/javascript" nonce="' in response.data
    
    # Extract nonce from HTML
    nonce_pattern = rb'<script type="text/javascript" nonce="([^"]+)">'
    match = re.search(nonce_pattern, response.data)
    assert match is not None
    nonce = match.group(1).decode('utf-8')
    
    # Nonce should be non-empty and of reasonable length
    assert len(nonce) > 10


def test_security_headers_present(client):
    """Test that Flask-Talisman security headers are present"""
    response = client.get("/")
    assert response.status_code == 200
    
    # Check CSP header is present and doesn't contain unsafe-inline for scripts
    csp_header = response.headers.get('Content-Security-Policy')
    assert csp_header is not None
    assert 'script-src' in csp_header
    assert 'nonce-' in csp_header
    # Style-src still needs unsafe-inline for Bootstrap, but script-src should use nonce
    assert "script-src 'self' 'nonce-" in csp_header
    
    # Check other security headers (Flask-Talisman defaults)
    assert response.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert response.headers.get('X-Content-Type-Options') == 'nosniff'
    
    # Ensure deprecated X-XSS-Protection header is not present
    assert 'X-XSS-Protection' not in response.headers


def test_configurable_pattern_validation():
    """Test that configurable password validation pattern works in validation function"""
    import portal
    
    # Test characters that should be allowed with expanded pattern
    errors = portal.validate_input("test@user.com", "testpass")
    assert "Username contains invalid characters" not in ' '.join(errors)
    
    # Test expanded character set (should be allowed)
    errors = portal.validate_input("test+user#1", "testpass") 
    assert "Username contains invalid characters" not in ' '.join(errors)
    
    # Test characters that should still be rejected (like spaces)
    errors = portal.validate_input("test user", "testpass")
    assert "Username contains invalid characters" in ' '.join(errors)
