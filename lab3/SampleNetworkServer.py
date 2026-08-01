import threading
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import infinc
import time
import math
import socket
import fcntl
import os
import errno
import secrets
import hmac
import hashlib

AUTH_SECRET_ENV = "THERMOMETER_PASSWORD"
SESSION_TTL_SECONDS = 300
CHALLENGE_TTL_SECONDS = 30
MAX_SESSIONS = 32
MAX_CHALLENGES = 64


class SmartNetworkThermometer(threading.Thread):
    # Only the authentication handshake is accepted before authentication.
    open_cmds = ["AUTH_CHALLENGE", "AUTH_RESPONSE"]
    prot_cmds = ["SET_DEGF", "SET_DEGC", "SET_DEGK", "GET_TEMP", "UPDATE_TEMP", "LOGOUT"]

    def __init__(self, source, updatePeriod, port):
        threading.Thread.__init__(self, daemon=True)
        # Set daemon to true, so it doesn't block program from exiting.
        self.source = source
        self.updatePeriod = updatePeriod
        self.curTemperature = 0
        self.updateTemperature()

        # Patch for hardcoded password:
        # The authentication secret is read from an environment variable instead
        # of being stored directly in the source code.
        auth_secret = os.environ.get(AUTH_SECRET_ENV)
        if not auth_secret:
            raise RuntimeError(
                "Missing authentication secret. Set the THERMOMETER_PASSWORD "
                "environment variable before starting the server."
            )
        self.auth_secret = auth_secret.encode("utf-8")

        # Patch for unbounded token list:
        # Sessions and login challenges are stored in dictionaries with size and
        # expiration enforcement instead of an always-growing token list.
        self.sessions = {}
        self.challenges = {}

        self.serverSocket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.serverSocket.bind(("127.0.0.1", port))
        fcntl.fcntl(self.serverSocket, fcntl.F_SETFL, os.O_NONBLOCK)

        self.deg = "K"

    def setSource(self, source):
        self.source = source

    def setUpdatePeriod(self, updatePeriod):
        self.updatePeriod = updatePeriod

    def setDegreeUnit(self, s):
        self.deg = s
        if self.deg not in ["F", "K", "C"]:
            self.deg = "K"

    def updateTemperature(self):
        self.curTemperature = self.source.getTemperature()

    def getTemperature(self):
        if self.deg == "C":
            return self.curTemperature - 273
        if self.deg == "F":
            return (self.curTemperature - 273) * 9 / 5 + 32

        return self.curTemperature

    def cleanupExpiredAuthState(self):
        """Remove expired sessions and challenges before accepting new work."""
        now = time.time()
        self.sessions = {
            session_id: session
            for session_id, session in self.sessions.items()
            if session["expires_at"] > now
        }
        self.challenges = {
            challenge_key: challenge
            for challenge_key, challenge in self.challenges.items()
            if challenge["expires_at"] > now
        }

    def enforceChallengeLimit(self):
        """Keep pending authentication challenges bounded."""
        while len(self.challenges) >= MAX_CHALLENGES:
            oldest_key = min(self.challenges, key=lambda key: self.challenges[key]["created_at"])
            del self.challenges[oldest_key]

    def sendText(self, text, addr):
        self.serverSocket.sendto(text.encode("utf-8"), addr)

    def expectedAuthProof(self, client_nonce, server_nonce):
        message = f"AUTH|{client_nonce}|{server_nonce}".encode("utf-8")
        return hmac.new(self.auth_secret, message, hashlib.sha256).hexdigest()

    def deriveSessionKey(self, client_nonce, server_nonce, session_id):
        message = f"SESSION|{client_nonce}|{server_nonce}|{session_id}".encode("utf-8")
        return hmac.new(self.auth_secret, message, hashlib.sha256).digest()

    def startAuthentication(self, msg, addr):
        """Create a one-time challenge without receiving the password."""
        parts = msg.split(" ")
        if len(parts) != 2 or not parts[1]:
            self.sendText("Bad Auth Challenge\n", addr)
            return

        self.cleanupExpiredAuthState()
        self.enforceChallengeLimit()

        client_nonce = parts[1]
        server_nonce = secrets.token_urlsafe(24)
        self.challenges[(client_nonce, server_nonce)] = {
            "created_at": time.time(),
            "expires_at": time.time() + CHALLENGE_TTL_SECONDS,
        }
        self.sendText(f"CHALLENGE {server_nonce}\n", addr)

    def finishAuthentication(self, msg, addr):
        """Verify the HMAC proof and create a bounded authenticated session."""
        parts = msg.split(" ")
        if len(parts) != 4:
            self.sendText("Bad Auth Response\n", addr)
            return

        _, client_nonce, server_nonce, proof = parts
        self.cleanupExpiredAuthState()

        challenge_key = (client_nonce, server_nonce)
        if challenge_key not in self.challenges:
            self.sendText("Bad Challenge\n", addr)
            return

        expected = self.expectedAuthProof(client_nonce, server_nonce)
        if not hmac.compare_digest(expected, proof):
            self.sendText("Authentication Failed\n", addr)
            del self.challenges[challenge_key]
            return

        # Enforce a hard cap so repeated authentication cannot grow memory forever.
        if len(self.sessions) >= MAX_SESSIONS:
            self.sendText("Too Many Sessions\n", addr)
            del self.challenges[challenge_key]
            return

        session_id = secrets.token_urlsafe(24)
        self.sessions[session_id] = {
            "key": self.deriveSessionKey(client_nonce, server_nonce, session_id),
            "created_at": time.time(),
            "expires_at": time.time() + SESSION_TTL_SECONDS,
            "last_counter": 0,
        }
        del self.challenges[challenge_key]
        self.sendText(f"OK {session_id} {SESSION_TTL_SECONDS}\n", addr)

    def expectedCommandMac(self, session, session_id, counter, command_text):
        message = f"{session_id}|{counter}|{command_text}".encode("utf-8")
        return hmac.new(session["key"], message, hashlib.sha256).hexdigest()

    def processAuthenticatedCommands(self, msg, addr, session_id):
        cmds = msg.split(';')
        for c in cmds:
            if c == "SET_DEGF":
                self.deg = "F"
            elif c == "SET_DEGC":
                self.deg = "C"
            elif c == "SET_DEGK":
                self.deg = "K"
            elif c == "GET_TEMP":
                self.serverSocket.sendto(b"%f\n" % self.getTemperature(), addr)
            elif c == "UPDATE_TEMP":
                self.updateTemperature()
            elif c == "LOGOUT":
                if session_id in self.sessions:
                    del self.sessions[session_id]
                self.sendText("Logged Out\n", addr)
            elif c:
                self.sendText("Invalid Command\n", addr)

    def processSecureCommand(self, msg, addr):
        """Validate the signed command envelope before running any command."""
        semi = msg.find(';')
        if semi == -1:
            self.sendText("Bad Command\n", addr)
            return

        header = msg[:semi].split(' ')
        command_text = msg[semi + 1:]
        if len(header) != 4 or header[0] != "SECURE":
            self.sendText("Bad Command\n", addr)
            return

        _, session_id, counter_text, received_mac = header
        self.cleanupExpiredAuthState()

        if session_id not in self.sessions:
            self.sendText("Bad Session\n", addr)
            return

        session = self.sessions[session_id]
        try:
            counter = int(counter_text)
        except ValueError:
            self.sendText("Bad Counter\n", addr)
            return

        # Require strictly increasing counters to prevent replay of old commands.
        if counter <= session["last_counter"]:
            self.sendText("Replay Detected\n", addr)
            return

        expected_mac = self.expectedCommandMac(session, session_id, counter, command_text)
        if not hmac.compare_digest(expected_mac, received_mac):
            self.sendText("Bad MAC\n", addr)
            return

        session["last_counter"] = counter
        session["expires_at"] = time.time() + SESSION_TTL_SECONDS
        self.processAuthenticatedCommands(command_text, addr, session_id)

    def run(self):  # The running function.
        while True:
            try:
                msg, addr = self.serverSocket.recvfrom(1024)
                msg = msg.decode("utf-8").strip()

                if msg.startswith("AUTH_CHALLENGE "):
                    self.startAuthentication(msg, addr)
                elif msg.startswith("AUTH_RESPONSE "):
                    self.finishAuthentication(msg, addr)
                elif msg.startswith("SECURE "):
                    self.processSecureCommand(msg, addr)
                else:
                    self.sendText("Authenticate First\n", addr)

            except IOError as e:
                if e.errno == errno.EWOULDBLOCK:
                    # Do nothing.
                    pass
                else:
                    # Do nothing for now.
                    pass
                msg = ""

            self.cleanupExpiredAuthState()
            self.updateTemperature()
            time.sleep(self.updatePeriod)


class SimpleClient:
    def __init__(self, therm1, therm2):
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
        self.infTherm = therm1
        self.incTherm = therm2

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

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

    def updateInfTemp(self, frame):
        self.updateTime()
        self.infTemps.append(self.infTherm.getTemperature() - 273)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def updateIncTemp(self, frame):
        self.updateTime()
        self.incTemps.append(self.incTherm.getTemperature() - 273)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,


UPDATE_PERIOD = .05  # In seconds.
SIMULATION_STEP = .1  # In seconds.

# Create a new instance of IncubatorSimulator.
bob = infinc.Human(mass=8, length=1.68, temperature=36 + 273)
bobThermo = SmartNetworkThermometer(bob, UPDATE_PERIOD, 23456)
bobThermo.start()  # Start the thread.

inc = infinc.Incubator(width=1, depth=1, height=1, temperature=37 + 273, roomTemperature=20 + 273)
incThermo = SmartNetworkThermometer(inc, UPDATE_PERIOD, 23457)
incThermo.start()  # Start the thread.

incHeater = infinc.SmartHeater(powerOutput=1500, setTemperature=45 + 273, thermometer=incThermo, updatePeriod=UPDATE_PERIOD)
inc.setHeater(incHeater)
incHeater.start()  # Start the thread.

sim = infinc.Simulator(infant=bob, incubator=inc, roomTemp=20 + 273, timeStep=SIMULATION_STEP, sleepTime=SIMULATION_STEP / 10)
sim.start()

sc = SimpleClient(bobThermo, incThermo)

plt.grid()
plt.show()
