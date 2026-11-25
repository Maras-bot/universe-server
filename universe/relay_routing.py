"""
Instradamento multi-account e "Trova telefono" del relay (v0.6). Puro Python, testabile.

Config (file JSON indicato da RELAY_ACCOUNTS_FILE, MAI token in chiaro):
{
  "accounts": [
    {"id": "maras",
     "identifiers": ["+39 333 1234567", "mignani.maras@gmail.com"],
     "token_sha256": "<sha256 esadecimale del token dell'account>",
     "devices": [{"device_id": "pixel", "label": "Pixel"}, {"device_id": "tab", "label": "Tablet"}]}
  ]
}

Regole:
- un token identifica UN account; un telefono si registra solo se il suo device_id è
  tra i dispositivi abbinati di quell'account;
- "ring" cerca il bersaglio SOLO tra i dispositivi dello stesso account: per device_id,
  oppure per numero/email dell'account (= tutti gli altri suoi dispositivi online);
- mai numeri arbitrari, mai SMS: un identificativo che non è dell'account viene rifiutato;
- limite: massimo RING_MAX squilli per account ogni RING_WINDOW secondi.
"""
import hashlib
import hmac
import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

RING_MAX = 3
RING_WINDOW = 60.0


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def identifier_hash(s: str) -> str:
    """Hash dell'identificativo (telefono/email) normalizzato: è l'unica forma salvata."""
    return sha256_hex(normalize_identifier(s))


def normalize_identifier(s: str) -> str:
    """Email in minuscolo; telefono: solo cifre (con + iniziale), 00 → +."""
    s = (s or "").strip()
    if "@" in s:
        return s.lower()
    digits = re.sub(r"[^\d+]", "", s)
    if digits.startswith("00"):
        digits = "+" + digits[2:]
    return digits


HEARTBEAT_TIMEOUT = 20 * 60  # secondi


@dataclass
class Device:
    device_id: str
    label: str = ""


@dataclass
class Account:
    id: str
    token_sha256: str
    # SOLO hash SHA-256 dell'identificativo normalizzato: numeri ed email non si salvano in chiaro.
    identifier_sha256: List[str] = field(default_factory=list)
    devices: List[Device] = field(default_factory=list)

    def device(self, device_id: str) -> Optional[Device]:
        return next((d for d in self.devices if d.device_id == device_id), None)

    def owns_identifier(self, ident: str) -> bool:
        n = normalize_identifier(ident)
        return bool(n) and identifier_hash(n) in self.identifier_sha256


class RouteError(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code = code
        self.msg = msg


class Registry:
    def __init__(self, accounts: List[Account], clock=time.monotonic):
        self._beats: Dict[Tuple[str, str], dict] = {}
        self.accounts: Dict[str, Account] = {a.id: a for a in accounts}
        self.online: Dict[Tuple[str, str], object] = {}   # (account, device) -> connessione
        self._rings: Dict[str, List[float]] = {}
        self.clock = clock

    @staticmethod
    def from_json(text: str, clock=time.monotonic) -> "Registry":
        data = json.loads(text)
        accs = []
        for a in data.get("accounts", []):
            if "identifiers" in a:
                raise ValueError("identificativi in chiaro non ammessi: usa identifier_sha256 (python routing.py hash <numero o email>)")
            accs.append(Account(
                id=a["id"], token_sha256=a["token_sha256"].lower(),
                identifier_sha256=[h.lower() for h in a.get("identifier_sha256", [])],
                devices=[Device(d["device_id"], d.get("label", "")) for d in a.get("devices", [])]))
        return Registry(accs, clock)

    # --- autenticazione ---
    def account_for_token(self, token: Optional[str]) -> Account:
        if not token:
            raise RouteError(401, "token mancante")
        h = sha256_hex(token)
        for a in self.accounts.values():
            if hmac.compare_digest(a.token_sha256, h):
                return a
        raise RouteError(401, "token non valido")

    def register_phone(self, token: Optional[str], device_id: Optional[str], conn: object,
                       account_id: Optional[str] = None) -> Tuple[Account, Device]:
        acc = self.account_for_token(token)
        if account_id and account_id != acc.id:
            raise RouteError(403, "account non corrispondente al token")
        dev = acc.device(device_id or "")
        if dev is None:
            raise RouteError(403, "dispositivo non abbinato a questo account")
        self.online[(acc.id, dev.device_id)] = conn
        return acc, dev

    def unregister(self, account_id: str, device_id: str, conn: object) -> None:
        if self.online.get((account_id, device_id)) is conn:
            self.online.pop((account_id, device_id), None)

    def online_devices(self, account_id: str) -> List[str]:
        return [d for (a, d) in self.online if a == account_id]

    # --- comandi ---
    def route_command(self, acc: Account, cmd: dict) -> Tuple[str, dict]:
        """Sceglie il dispositivo per un comando. Ritorna (device_id, comando con account)."""
        if cmd.get("account") not in (None, acc.id):
            raise RouteError(403, "comando per un altro account")
        target = cmd.get("device_id")
        online = self.online_devices(acc.id)
        if target is None:
            if len(online) != 1:
                raise RouteError(400 if online else 503, "indica device_id" if online else "nessun dispositivo connesso")
            target = online[0]
        if acc.device(target) is None:
            raise RouteError(404, "dispositivo sconosciuto per questo account")
        if (acc.id, target) not in self.online:
            raise RouteError(503, "dispositivo non connesso")
        out = dict(cmd)
        out["account"] = acc.id
        out.pop("device_id", None)
        return target, out

    # --- trova telefono ---
    def resolve_ring(self, acc: Account, target: str, from_device: Optional[str] = None) -> List[str]:
        """Dispositivi da far suonare. Solo dello stesso account; mai sé stessi."""
        if not target:
            raise RouteError(400, "bersaglio mancante")
        if acc.device(target) is not None:
            devs = [target]
        elif acc.owns_identifier(target):
            devs = [d.device_id for d in acc.devices]
        else:
            # Numero/email/id che non appartiene all'account: rifiutato, nessun tentativo altrove.
            raise RouteError(404, "bersaglio non trovato tra i tuoi dispositivi")
        devs = [d for d in devs if d != from_device]
        online = [d for d in devs if (acc.id, d) in self.online]
        if not online:
            raise RouteError(503, "nessun dispositivo raggiungibile")
        return online

    def check_ring_rate(self, account_id: str) -> None:
        now = self.clock()
        hist = [t for t in self._rings.get(account_id, []) if now - t < RING_WINDOW]
        if len(hist) >= RING_MAX:
            self._rings[account_id] = hist
            raise RouteError(429, "troppi squilli: riprova tra poco")
        hist.append(now)
        self._rings[account_id] = hist

    # --- avviso accessibilità spenta: battito ogni 10 min, allarme se manca da più di 20 ---
    def heartbeat(self, account_id: str, device_id: str, alert_others: bool) -> None:
        self._beats[(account_id, device_id)] = {"t": self.clock(), "alert": bool(alert_others), "alerted": False}

    def heartbeat_stop(self, account_id: str, device_id: str) -> None:
        """Spento volutamente o funzione spenta: non si aspetta più nessun battito."""
        self._beats.pop((account_id, device_id), None)

    def stale_alerts(self) -> List[Tuple[str, str, List[str]]]:
        """(account, dispositivo muto, altri dispositivi online dello STESSO account). Una volta per episodio."""
        out = []
        now = self.clock()
        for (a, d), b in self._beats.items():
            if b["alerted"] or not b["alert"] or now - b["t"] <= HEARTBEAT_TIMEOUT:
                continue
            b["alerted"] = True
            out.append((a, d, [x for x in self.online_devices(a) if x != d]))
        return out

    def a11y_off_command(self, acc: Account, device_id: str) -> dict:
        label = acc.device(device_id).label if acc.device(device_id) else device_id
        return {"action": "accessibility_off_notice", "account": acc.id, "from": label}

    # --- allarme notturno: avviso agli altri dispositivi dello stesso account ---
    def alert_targets(self, acc: Account, from_device: Optional[str]) -> List[str]:
        return [d for d in self.online_devices(acc.id) if d != from_device]

    def alert_command(self, acc: Account, from_device: Optional[str], msg: dict) -> dict:
        label = acc.device(from_device).label if from_device and acc.device(from_device) else "dispositivo"
        return {"action": "night_alarm_notice", "account": acc.id, "from": label,
                "hhmm": str(msg.get("hhmm", ""))[:5], "label": str(msg.get("label", ""))[:60]}

    def ring_command(self, acc: Account, from_device: Optional[str]) -> dict:
        label = acc.device(from_device).label if from_device and acc.device(from_device) else "relay"
        return {"action": "ring_start", "account": acc.id, "from": label}


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 3 and sys.argv[1] == "hash":
        print(identifier_hash(sys.argv[2]))
    else:
        print("uso: python routing.py hash <numero o email>")
