#!/usr/bin/env python3
import argparse, binascii, hashlib, hmac

def prf512(pmk: bytes, a: bytes, b: bytes) -> bytes:
    """PRF-512 (Pairwise key expansion) using HMAC-SHA1 -> 64 bytes"""
    output = b""
    counter = 1
    while len(output) < 64:
        h = hmac.new(pmk, None, hashlib.sha1)
        h.update(a)
        h.update(b'\x00')
        h.update(b)
        h.update(bytes([counter]))
        output += h.digest()
        counter += 1
    return output[:64]

def mac_from_str(s: str) -> bytes:
    s = s.replace(':','').replace('-','').lower()
    return binascii.unhexlify(s)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--password", required=True)
    parser.add_argument("-s","--ssid", required=True)
    parser.add_argument("--ap", default="001122334455", help="AP MAC (hex, default 001122334455)")
    parser.add_argument("--sta", default="aabbccddeeff", help="STA MAC (hex default aabbccddeeff)")
    args = parser.parse_args()

    passphrase = args.password
    ssid = args.ssid

    # reproducible nonces for lab (32 bytes each)
    anonce = binascii.unhexlify("a0" * 32)
    snonce = binascii.unhexlify("b1" * 32)

    ap_mac = mac_from_str(args.ap)
    sta_mac = mac_from_str(args.sta)

    # simple EAPOL-like blob for demo — MIC field must be zeroed in the blob used for MIC calc
    eapol = b"TestEAPOLDataForDemo" + b"\x00" * 16  # reserve 16 bytes for MIC (zeroed)

    # PMK = PBKDF2(passphrase, ssid, 4096, 32)
    pmk = hashlib.pbkdf2_hmac('sha1', passphrase.encode('utf-8'), ssid.encode('utf-8'), 4096, dklen=32)

    # build B: min(mac)||max(mac)||min(anonce)||max(anonce)
    macs = (ap_mac, sta_mac) if ap_mac < sta_mac else (sta_mac, ap_mac)
    nonces = (anonce, snonce) if anonce < snonce else (snonce, anonce)
    B = macs[0] + macs[1] + nonces[0] + nonces[1]

    A = b"Pairwise key expansion"
    ptk = prf512(pmk, A, B)  # 64 bytes
    kck = ptk[0:16]

    # MIC = HMAC-SHA1-128 (first 16 bytes of HMAC-SHA1)
    mic_full = hmac.new(kck, eapol, hashlib.sha1).digest()
    mic = mic_full[:16]

    out_fields = [
        ssid,
        ap_mac.hex(),
        sta_mac.hex(),
        anonce.hex(),
        snonce.hex(),
        eapol.hex(),
        mic.hex()
    ]
    out = "*".join(out_fields)
    with open("test_wpa2.txt", "w", encoding="utf-16") as f:
        f.write(out)

    print("Wrote test_wpa2.txt (utf-16).")
    print("Passphrase used (for testing):", passphrase)

if __name__ == "__main__":
    main()
