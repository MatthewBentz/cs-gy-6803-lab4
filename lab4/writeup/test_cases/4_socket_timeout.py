import socket
import time
from SampleNetworkClient import SimpleNetworkClient

def test_udp_timeout_protection():
    """
    Description: This test is to determine if the client will stop waiting indefinitely when a UDP server does not respond.
    
    Pre Condition: The patch is on line 67 of SampleNetworkClient.py. Depending on if that line is implemented, the result of the test is the positive case and negative if the patch is not implemented.

    Explantion: Sends a UDP request to a port where no server is running. The test passes if the client exists after the timeout period instead of blocking indefinitely.

    Passed Case:
        - Client sends the UDP request
        - Socket timeout occurs after the configured timeout period
        - Client exists gracefully instead of waiting indefinitely

    Failed Case:
        - Client sends the UDP request
        - Client waits indefinitely for a server response
        - Client becomes unavailable due to a blocked connection
    """

    # Create client object without running GUI updates.
    client = SimpleNetworkClient.__new__(SimpleNetworkClient)

    # Port with no server listening.
    unused_port = 65000

    start = time.time()

    try:
        client.sendAndReceive(
            unused_port,
            "AUTH_CHALLENGE test"
        )

        # If no exception occurs, something unexpected happened.
        print("FAIL: Client did not timeout when server did not respond.")
        assert False

    except socket.timeout:
        elapsed = time.time() - start

        # Verify timeout duration (expected - 2s)
        assert elapsed < 5

        print("PASS: Client timed out correctly when server did not respond.")

    except Exception as ex:
        print(f"FAIL: Unexpected exception: {ex}")
        assert False


if __name__ == "__main__":
    test_udp_timeout_protection()