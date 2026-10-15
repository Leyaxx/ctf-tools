# PHANTOM SHELL X — The Ultimate CTF Decoder

```
╔══════════════════════════════════════════════════════════════════╗
║   PHANTOM SHELL X  —  The Ultimate CTF Decoder                 ║
║   v4.2.0 | Codename: NIGHTHAWK                                 ║
║   "If the flag exists, NIGHTHAWK will find it."                 ║
╚══════════════════════════════════════════════════════════════════╝
```

## Overview

All-in-one CTF challenge solving framework. Built for speed, built for flags.

Designed for **Root-Me**, **HackTheBox**, **TryHackMe**, **picoCTF** and more.

## Modules

| # | Module | Description |
|---|--------|-------------|
| 01 | **Crypto Solver** | Caesar, ROT13/47, XOR bruteforce, Vigenere + Kasiski, Rail Fence, AES/RSA decrypt, frequency analysis, hash identification, Atbash, Affine cipher, Morse code, multi-layer Base64 |
| 02 | **Network Analyzer** | PCAP parser, Ethernet/IPv4/TCP/UDP/DNS/HTTP dissector, TCP stream extraction, port scanner, service identification |
| 03 | **Binary Toolkit** | ELF header parser, string extractor, shellcode disassembler, ROP chain builder, format string payload generator, cyclic pattern generator, binary protection checker |
| 04 | **Forensics Engine** | File identification (magic bytes), file carving, EXIF extraction, LSB steganography, entropy analysis, hex dump |
| 05 | **Web Exploit Scanner** | SQLi / XSS / SSTI / LFI / CMDi payload database, WAF detection, UNION-based SQLi generator, SSTI template probes, URL encoding |
| 06 | **Flag Extractor** | Pattern matching for FLAG{}, CTF{}, HTB{}, THM{}, picoCTF{}, RM{} and custom formats. Recursive file/directory scanning |
| 07 | **Recon Toolkit** | Directory bruteforce wordlist, subdomain enumeration, robots.txt parser, user-agent rotation, WHOIS lookup |

## Requirements

- Python 3.8+
- No external dependencies (stdlib only)

## Usage

### Standalone

```bash
python3 PHANTOM_SHELL_X.py
```

### As a library

```python
from PHANTOM_SHELL_X import CryptoSolver, NetworkAnalyzer, BinaryToolkit

# Crypto
crypto = CryptoSolver()
results = crypto.caesar_bruteforce("Uryyb Jbeyq")
print(results[13])  # "Hello World"

# XOR bruteforce
decoded = crypto.xor_bruteforce(b"\x1d\x06\x1a\x1a\x19")
print(decoded[0]["decoded"])

# Vigenere
plaintext = crypto.vigenere_decode("LXFOPVEFRNHR", "LEMON")
print(plaintext)

# Hash identification
print(crypto.hash_identify("5d41402abc4b2a76b9719d911017c592"))
# ['MD5', 'NTLM']
```

### Binary Analysis

```python
binary = BinaryToolkit()

# Parse ELF
elf = binary.parse_elf_header("/path/to/binary")
print(elf)

# Generate cyclic pattern for buffer overflow
pattern = binary.cyclic_pattern(500)
offset = binary.find_pattern_offset(pattern, 0x41366241)
print(f"Offset: {offset}")

# Disassemble shellcode
listing = binary.disassemble_shellcode("9090905589e531c0cd80c3")
for line in listing:
    print(line)

# Check binary protections
protections = binary.check_protections("/path/to/binary")
print(protections)
```

### Network / PCAP

```python
net = NetworkAnalyzer()

# Parse PCAP file
result = net.analyze_pcap_file("capture.pcap")
print(f"Packets: {result['packet_count']}")

# Extract TCP streams
streams = net.extract_streams(result["packets"])
for key, data in streams.items():
    print(f"{key}: {len(data)} bytes")
```

### Forensics

```python
forensics = ForensicsEngine()

# Identify file type
info = forensics.identify_file("mystery_file")
print(info)  # {'type': 'PNG', 'ext': 'png'}

# Carve embedded files
carved = forensics.carve_files("suspicious.bin")
for f in carved:
    print(f"{f['type']} at offset {f['offset_hex']}")

# Entropy analysis (detect encrypted/compressed sections)
entropy = forensics.analyze_entropy("firmware.bin")
for block in entropy:
    if block["is_high"]:
        print(f"High entropy at {block['offset_hex']}: {block['entropy']}")
```

### Web

```python
web = WebExploitScanner()

# Get SQLi payloads
for payload in web.get_payloads("sqli"):
    print(payload)

# Generate UNION payloads
union_payloads = web.generate_sqli_union(max_columns=8)

# Detect WAF
headers = {"Server": "cloudflare", "cf-ray": "abc123"}
print(web.detect_waf(headers))  # ['Cloudflare']
```

### Flag Hunting

```python
flags = FlagExtractor()

# Scan a string
flags.scan_string("The answer is FLAG{n1ghth4wk_w4s_h3r3}")

# Scan an entire directory
found = flags.scan_directory("/path/to/ctf/files")
for filepath, results in found.items():
    for f in results:
        print(f"[{f['pattern']}] {f['flag']} in {filepath}")
```

## Supported Flag Formats

| Format | Pattern |
|--------|---------|
| Standard | `FLAG{...}` |
| CTF | `CTF{...}` |
| HackTheBox | `HTB{...}` |
| TryHackMe | `THM{...}` |
| picoCTF | `picoCTF{...}` |
| Root-Me | `RM{...}` |

## License

For authorized CTF competitions and security research only.

---

*GhostNet CTF Division — NIGHTHAWK v4.2.0*
