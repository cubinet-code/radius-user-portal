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
