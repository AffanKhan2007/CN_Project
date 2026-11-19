"""Shared helpers: config, hashing, challenge-response, logging."""
import hashlib, hmac, json, logging, os, secrets

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_DIR = os.path.join(BASE, "config")
LOG_DIR = os.path.join(BASE, "logs")
os.makedirs(LOG_DIR, exist_ok=True)


def load_json(name):
    with open(os.path.join(CONFIG_DIR, name)) as f:
        return json.load(f)


CFG = load_json("config.json")
NET = CFG["network"]
AUTH_IP = os.environ.get("AUTH_IP", NET["auth_ip"])
PROTECTED_IP = os.environ.get("PROTECTED_IP", NET["protected_ip"])
CTRL_IP = os.environ.get("CTRL_IP", NET["controller_ip"])
AUTH_PORT = int(os.environ.get("AUTH_PORT", NET["auth_port"]))
EVENT_PORT = int(os.environ.get("EVENT_PORT", NET["event_port"]))
WEB_PORT = int(os.environ.get("WEB_PORT", NET["web_port"]))
DATA_PORT = int(os.environ.get("DATA_PORT", NET["data_port"]))


def pw_hash(password):
    return hashlib.sha256(password.encode()).hexdigest()


def new_nonce():
    return secrets.token_hex(16)


def challenge_response(pwd_hash_hex, nonce):
    """HMAC-SHA256(key = sha256(password), msg = nonce). Password never crosses the wire."""
    return hmac.new(pwd_hash_hex.encode(), nonce.encode(), hashlib.sha256).hexdigest()


def get_logger(name, filename, console=True):
    log = logging.getLogger(name)
    if log.handlers:
        return log
    log.setLevel(logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh = logging.FileHandler(os.path.join(LOG_DIR, filename))
    fh.setFormatter(fmt)
    log.addHandler(fh)
    if console:
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        log.addHandler(sh)
    log.propagate = False
    return log
