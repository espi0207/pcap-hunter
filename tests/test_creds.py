import base64

from pcaphunter.creds import CredentialSniffer, mask
from pcaphunter.decode import Packet


def tcp(payload: bytes, dport: int, sport: int = 50000) -> Packet:
    return Packet(
        ts=1.0, length=100, src="10.0.0.2", dst="10.0.0.1", proto="TCP", sport=sport, dport=dport, payload=payload
    )


def sniff(*packets):
    sniffer = CredentialSniffer()
    return [(c.protocol, c.user, c.secret) for p in packets for c in sniffer.feed(p)]


def test_http_basic():
    auth = base64.b64encode(b"admin:secreto1").decode()
    request = f"GET / HTTP/1.1\r\nHost: x\r\nAuthorization: Basic {auth}\r\n\r\n".encode()
    assert sniff(tcp(request, 80)) == [("HTTP Basic", "admin", "secreto1")]


def test_http_bearer_token():
    request = b"GET /api HTTP/1.1\r\nAuthorization: Bearer abc.def.ghi\r\n\r\n"
    assert sniff(tcp(request, 8080)) == [("HTTP Bearer", None, "abc.def.ghi")]


def test_http_login_form():
    body = b"email=ana%40example.com&password=Gato%2A1"
    request = b"POST /login HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + body
    assert sniff(tcp(request, 80)) == [("formulario HTTP", "ana@example.com", "Gato*1")]


def test_http_without_credentials():
    assert sniff(tcp(b"GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n", 80)) == []


def test_ftp_user_then_pass():
    assert sniff(tcp(b"USER juan\r\n", 21), tcp(b"PASS 1234abcd\r\n", 21)) == [("FTP", "juan", "1234abcd")]


def test_ftp_user_and_pass_of_different_connections_are_not_mixed():
    found = sniff(tcp(b"USER juan\r\n", 21, sport=1), tcp(b"PASS otra\r\n", 21, sport=2))
    assert found == [("FTP", None, "otra")]


def test_anonymous_ftp_is_not_a_secret():
    assert sniff(tcp(b"USER anonymous\r\n", 21), tcp(b"PASS guest@\r\n", 21)) == []


def test_pop3_and_imap():
    assert sniff(tcp(b"USER eva\r\n", 110), tcp(b"PASS clave\r\n", 110)) == [("POP3", "eva", "clave")]
    assert sniff(tcp(b'a001 LOGIN "eva" "mi clave"\r\n', 143)) == [("IMAP", "eva", "mi clave")]


def test_smtp_auth_plain_and_login():
    plain = base64.b64encode(b"\0eva@example.com\0clave").decode()
    assert sniff(tcp(f"AUTH PLAIN {plain}\r\n".encode(), 587)) == [("SMTP AUTH PLAIN", "eva@example.com", "clave")]
    user = base64.b64encode(b"eva").decode().encode()
    password = base64.b64encode(b"clave").decode().encode()
    found = sniff(tcp(b"AUTH LOGIN\r\n", 25), tcp(user + b"\r\n", 25), tcp(password + b"\r\n", 25))
    assert found == [("SMTP AUTH LOGIN", "eva", "clave")]


def test_mask():
    assert mask("Verano2026!") == "V… (11 caracteres)"
    assert "Verano" not in mask("Verano2026!")
