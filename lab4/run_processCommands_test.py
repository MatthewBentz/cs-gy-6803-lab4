import os
from SampleNetworkServer import SmartNetworkThermometer

class DummySource:
    def getTemperature(self):
        return 300.0

def test_logout_authorization():
    """
    Description: This test is to determine if a chain of commands is able to run even after a session logout.

    Pre Condition: The patch is on line 187 of SampleNetworkServer.py. Depending on if that line is implemented, the result of the test is the positive case and negative if the patch is not implemented.

    Explantion: Sends a LOGOUT command followed by SET_DEGF. The test passes if SET_DEGF is not executed after logout.

    Passed Case:
        - LOGOUT invalidates the session
        - Command processing stops immediately
        - Temperature unit remains unchanged

    Failed Case:
        - LOGOUT invalidates the session
        - Remaining commands continue executing
        - Temperature unit changed to Fahrenheit
    """
    os.environ["THERMOMETER_PASSWORD"] = "testpassword"

    therm = SmartNetworkThermometer(DummySource(), 0.1, 0)

    # Prevent UDP traffic during the test.
    therm.sendText = lambda *args, **kwargs: None

    # Simulate an authenticated session.
    session_id = "test-session"
    therm.sessions[session_id] = {
        "key": b"dummy",
        "created_at": 0,
        "expires_at": float("inf"),
        "last_counter": 0,
    }

    # Initial state
    therm.deg = "K"

    # Execute multiple commands in one request.
    therm.processAuthenticatedCommands(
        "LOGOUT;SET_DEGF",
        ("127.0.0.1", 9999),
        session_id,
    )

    # Positive case (patched)
    if therm.deg == "K":
        print("PASS: LOGOUT terminated command processing. No commands executed after session invalidation.")

    # Negative case (vulnerable)
    else:
        print("FAIL: Commands executed after LOGOUT. Authorization bypass vulnerability still exists.")
        raise AssertionError("SET_DEGF executed after LOGOUT")

if __name__ == "__main__":
    test_logout_authorization()