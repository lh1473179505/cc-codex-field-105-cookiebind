import hashlib
import hmac


def traffic_secret(master, generation, client_random, label):
    return hmac.new(master, f"{generation}:{client_random}:{label}".encode(), hashlib.sha256).hexdigest()


def keylog_line(client_random, label, secret):
    if label == "CLIENT_RANDOM":
        return f"CLIENT_RANDOM {client_random} {secret}"
    return f"{label} {client_random} {secret}"
