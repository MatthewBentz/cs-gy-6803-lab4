import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import math
import socket
import os
import getpass
import secrets
import hmac
import hashlib

AUTH_SECRET_ENV = "THERMOMETER_PASSWORD"
SESSION_TTL_SECONDS = 300
SOCKET_TIMEOUT_SECONDS = 2


class SimpleNetworkClient:
    def __init__(self, port1, port2):
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now - i)) for i in range(30, 0, -1)]
        self.infTemps = [0] * 30
        self.incTemps = [0] * 30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20, 50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infPort = port1
        self.incPort = port2

        # Patch for hardcoded password:
        # The password is not embedded in the source code. The user may provide it
        # through an environment variable or type it at runtime.
        self.auth_secret = self.loadAuthSecret()

        # One independent authenticated session is maintained per thermometer port.
        # The session id is not a bearer token. Each command must include a valid
        # HMAC and an increasing counter.
        self.sessions = {}

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

    def loadAuthSecret(self):
        auth_secret = os.environ.get(AUTH_SECRET_ENV)
        if auth_secret is None:
            auth_secret = getpass.getpass("Thermometer password: ")
        if not auth_secret:
            raise RuntimeError("A non-empty thermometer password is required.")
        return auth_secret.encode("utf-8")

    def updateTime(self):
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime):
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            # Last 30 seconds of data.
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times, rotation=45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def sendAndReceive(self, p, message):
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        s.settimeout(SOCKET_TIMEOUT_SECONDS)
        try:
            s.sendto(message.encode("utf-8"), ("127.0.0.1", p))
            msg, addr = s.recvfrom(1024)
            return msg.decode("utf-8").strip()
        finally:
            s.close()

    def expectedAuthProof(self, client_nonce, server_nonce):
        message = f"AUTH|{client_nonce}|{server_nonce}".encode("utf-8")
        return hmac.new(self.auth_secret, message, hashlib.sha256).hexdigest()

    def deriveSessionKey(self, client_nonce, server_nonce, session_id):
        message = f"SESSION|{client_nonce}|{server_nonce}|{session_id}".encode("utf-8")
        return hmac.new(self.auth_secret, message, hashlib.sha256).digest()

    def authenticate(self, p):
        """
        Authenticate without sending the password in plaintext.

        The client asks for a server challenge, proves knowledge of the shared
        secret with an HMAC, and derives a per-session command signing key.
        """
        client_nonce = secrets.token_urlsafe(24)
        challenge_response = self.sendAndReceive(p, f"AUTH_CHALLENGE {client_nonce}")
        challenge_parts = challenge_response.split(" ")
        if len(challenge_parts) != 2 or challenge_parts[0] != "CHALLENGE":
            raise RuntimeError(f"Authentication challenge failed: {challenge_response}")

        server_nonce = challenge_parts[1]
        proof = self.expectedAuthProof(client_nonce, server_nonce)
        auth_response = self.sendAndReceive(p, f"AUTH_RESPONSE {client_nonce} {server_nonce} {proof}")
        auth_parts = auth_response.split(" ")
        if len(auth_parts) != 3 or auth_parts[0] != "OK":
            raise RuntimeError(f"Authentication failed: {auth_response}")

        session_id = auth_parts[1]
        ttl = int(auth_parts[2])
        self.sessions[p] = {
            "session_id": session_id,
            "key": self.deriveSessionKey(client_nonce, server_nonce, session_id),
            "counter": 0,
            "expires_at": time.time() + ttl,
        }
        return self.sessions[p]

    def getSession(self, p):
        session = self.sessions.get(p)
        if session is None or session["expires_at"] <= time.time():
            return self.authenticate(p)
        return session

    def commandMac(self, session, command_text):
        message = f"{session['session_id']}|{session['counter']}|{command_text}".encode("utf-8")
        return hmac.new(session["key"], message, hashlib.sha256).hexdigest()

    def sendSecureCommand(self, p, command_text, retry=True):
        """Send a command with HMAC authentication and replay protection."""
        session = self.getSession(p)
        session["counter"] += 1
        mac = self.commandMac(session, command_text)
        packet = f"SECURE {session['session_id']} {session['counter']} {mac};{command_text}"
        response = self.sendAndReceive(p, packet)

        # If the server expired or removed the session, authenticate once and retry.
        if retry and response in ["Bad Session", "Replay Detected"]:
            self.sessions.pop(p, None)
            return self.sendSecureCommand(p, command_text, retry=False)

        if response in ["Bad MAC", "Bad Counter", "Bad Command", "Authenticate First"]:
            raise RuntimeError(f"Secure command failed: {response}")

        session["expires_at"] = time.time() + SESSION_TTL_SECONDS
        return response

    def getTemperatureFromPort(self, p):
        response = self.sendSecureCommand(p, "GET_TEMP")
        return float(response)

    def logout(self, p):
        if p in self.sessions:
            self.sendSecureCommand(p, "LOGOUT", retry=False)
            self.sessions.pop(p, None)

    def updateInfTemp(self, frame):
        self.updateTime()
        self.infTemps.append(self.getTemperatureFromPort(self.infPort) - 273)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame):
        self.updateTime()
        self.incTemps.append(self.getTemperatureFromPort(self.incPort) - 273)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,


snc = SimpleNetworkClient(23456, 23457)

plt.grid()
plt.show()
