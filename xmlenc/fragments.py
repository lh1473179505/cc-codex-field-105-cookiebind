import base64
import hashlib
import hmac
import xml.etree.ElementTree as ET


LEGACY_ALGORITHMS = {"rsa-oaep-mgf1p": "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"}


def parse_reference(fragment):
    root = ET.fromstring(fragment)
    reference = root.attrib.get("Id")
    if not reference:
        raise ValueError("encrypted fragment requires an Id")
    return reference, root


def seal(secret, generation, reference, plaintext):
    key = hmac.new(secret, f"{generation}:{reference}".encode(), hashlib.sha256).digest()
    raw = plaintext.encode()
    body = bytes(value ^ key[index % len(key)] for index, value in enumerate(raw))
    return base64.b64encode(body).decode()


def unseal(secret, generation, reference, encoded):
    key = hmac.new(secret, f"{generation}:{reference}".encode(), hashlib.sha256).digest()
    raw = base64.b64decode(encoded)
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(raw)).decode()
