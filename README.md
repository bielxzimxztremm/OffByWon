# OffByWon Fuzzing Framework Documentation

**Author:** Laurent Gaffié  
**Website:** https://secorizon.com  
**Twitter:** @secorizon  
**Version:** 1.0.0

---

## Table of Contents

1. [What is OffByWon?](#what-is-offbywon)
2. [Installation](#installation)
3. [Framework Components](#framework-components)
4. [Building Your First Fuzzer](#building-your-first-fuzzer)
5. [Field Types Reference](#field-types-reference)
6. [Fuzzing Modes](#fuzzing-modes)
7. [Command-Line Options](#command-line-options)
8. [Complete Example: Building a TCP Protocol Fuzzer](#complete-example-building-a-tcp-protocol-fuzzer)
9. [Array Overflow Testing](#array-overflow-testing)
10. [DER/ASN.1 Fuzzing](#derasn1-fuzzing)
11. [API Reference](#api-reference)

---

## What is OffByWon?

OffByWon is a Python framework primarily designed to find bugs in network protocols, however mutations from this framework can also be applied easily to file formats.

This framework allows you to perform structured fuzzing... With a bit of chaos. Several fuzzing mode -which can be combined- allows you to perform targeted chaos
in parsers, drivers, servers.

---

## Installation

OffByWon is a single Python file with no external dependencies beyond Python 3.6+.

```bash
# Download the framework
git clone https://github.com/secorizon/OffByWon.git

# Or copy to your project
cp offbywon.py /path/to/your/project/
```

To use it in your fuzzer:

```python
from offbywon import (
    ProtocolFuzzer,
    FieldType,
    Fuzzer,
    PacketBuilder,
    DERScanner,
    ArrayFuzzer,
    print_banner
)
```

---

## Framework Components

OffByWon has several building blocks you can use:

### 1. FieldType

Constants that define what kind of data a field contains:

```python
from offbywon import FieldType

FieldType.STRING   # Text data (filenames, paths, usernames)
FieldType.INT      # Numbers (flags, types, identifiers)
FieldType.LENGTH   # Size/count fields (how many bytes, how many items)
FieldType.OFFSET   # Pointers to other parts of the packet
FieldType.BYTES    # Raw binary data
FieldType.ASN_DER  # ASN.1/DER encoded data (certificates, Kerberos)
FieldType.ARRAY    # Lists of items
```

### 2. Fuzzer

The main fuzzing engine. Give it a field type and value, get back something weird:

```python
from offbywon import Fuzzer, FieldType

fuzzer = Fuzzer(mode='standard')

# Fuzz a length field that normally contains 4096
fuzzed_bytes, description = fuzzer.fuzz(FieldType.LENGTH, original=4096, size=4)
# Returns: (b'\xff\x0f\x00\x00', 'delta +1 (orig=4096, fuzzed=4097)')

# Fuzz a string field
fuzzed_bytes, description = fuzzer.fuzz(FieldType.STRING, original=b"test.txt", size=None)
# Returns: (b'%s%s%s%s%s%s%s%s%s%s', 'format_string (%s%s%s%s%s%s%s%s...)')
```

### 3. PacketBuilder

A helper to define and build packets:

```python
from offbywon import PacketBuilder, FieldType

# Define a simple packet structure
builder = PacketBuilder("MyPacket")
builder.add_field("Length", FieldType.LENGTH, size=4, default=0)
builder.add_field("Type", FieldType.INT, size=2, default=1)
builder.add_field("Flags", FieldType.INT, size=2, default=0)
builder.add_field("Filename", FieldType.STRING, default=b"test.txt")

# Build a clean packet
packet = builder.build()

# Build a fuzzed packet (automatically picks fields to fuzz)
fuzzed_packet, fuzz_info = builder.build_fuzzed(num_fields=1)
```

### 4. ProtocolFuzzer

The base class for building complete protocol fuzzers. You extend this class and implement the protocol-specific parts:

```python
from offbywon import ProtocolFuzzer

class MyFuzzer(ProtocolFuzzer):
    def get_protocol_name(self):
        return "MyProtocol"
    
    def get_available_targets(self):
        return ["connect", "read", "write"]
    
    def define_fuzz_fields(self):
        # Define what fields can be fuzzed for each target
        pass
    
    def run_fuzzing_session(self):
        # Send packets and check responses
        pass
```

### 5. DERScanner

Finds ASN.1/DER structures in binary data (used for protocols like Kerberos, LDAP, TLS):

```python
from offbywon import DERScanner

scanner = DERScanner(strict=False)
positions = scanner.scan(packet_bytes)

# Returns list of: (offset, type, description)
# Example: [(0, 'TAG', 'SEQUENCE/C (0x30)'), (1, 'LENGTH', 'len=45 (0x2d)'), ...]
```

### 6. ArrayFuzzer

Specialized helper for testing array overflow vulnerabilities (count field + elements):

```python
from offbywon import ArrayFuzzer

# Create array fuzzer for 2-byte count field
array_fuzz = ArrayFuzzer(count_size=2)
array_fuzz.add_raw_element(b'\x01\x00\x10\x00...')
array_fuzz.add_raw_element(b'\x02\x00\x08\x00...')

# Get fuzzed output
count_bytes, data_bytes, desc = array_fuzz.fuzz()
# Example: (b'\x10\x00', b'...', 'count_overflow (count=16, actual=2)')
```

See [Array Overflow Testing](#array-overflow-testing) for detailed usage.

---

## Building Your First Fuzzer

Let's build a fuzzer step by step. We'll create a fuzzer for a simple made-up protocol.

### Step 1: Understand the Protocol

First, understand what packets look like. Our example protocol has this structure:

```
Offset  Size  Field
------  ----  -----
0       4     Magic number (always 0x4F425731 = "OBW1")
4       4     Total packet length
8       2     Command type
10      2     Flags
12      4     Data length
16      N     Data
```

### Step 2: Create the Fuzzer Class

```python
#!/usr/bin/env python3
"""
Example fuzzer for a simple protocol.
"""

import socket
import struct
from offbywon import ProtocolFuzzer, FieldType, Fuzzer, print_banner


class SimpleFuzzer(ProtocolFuzzer):
    """Fuzzer for our simple example protocol."""
    
    def __init__(self, host, port):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = None
    
    def get_protocol_name(self):
        """Return the name of the protocol we're fuzzing."""
        return "SimpleProtocol"
    
    def get_available_targets(self):
        """Return list of things we can fuzz."""
        return ["header", "data"]
    
    def define_fuzz_fields(self):
        """
        Define what fields exist and how to fuzz them.
        
        Format: field_definitions[target] = {
            "FieldName": (FieldType.XXX, size_in_bytes),
            ...
        }
        """
        self.field_definitions["header"] = {
            "PacketLength": (FieldType.LENGTH, 4),
            "CommandType": (FieldType.INT, 2),
            "Flags": (FieldType.INT, 2),
            "DataLength": (FieldType.LENGTH, 4),
        }
        
        self.field_definitions["data"] = {
            "Filename": (FieldType.STRING, None),
        }
```

### Step 3: Add Connection Handling

```python
    def connect(self):
        """Connect to the target server."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect((self.host, self.port))
        print(f"[*] Connected to {self.host}:{self.port}")
    
    def disconnect(self):
        """Close the connection."""
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def _send_packet_impl(self, data, packet_type):
        """Actually send the packet over the network."""
        try:
            self.sock.sendall(data)
        except Exception as e:
            print(f"[!] Send error: {e}")
            raise
    
    def receive_response(self, size=4096):
        """Receive a response from the server."""
        try:
            return self.sock.recv(size)
        except socket.timeout:
            return None
        except Exception as e:
            print(f"[!] Receive error: {e}")
            return None
```

### Step 4: Build Packets

```python
    def build_packet(self, command_type, data, fuzz_fields=None):
        """
        Build a protocol packet.
        
        Args:
            command_type: The command type number
            data: The data payload
            fuzz_fields: Optional dict of fields to fuzz
        
        Returns:
            bytes: The complete packet
        """
        # Use fuzzed values if provided, otherwise use correct values
        fuzz_fields = fuzz_fields or {}
        
        # Calculate lengths
        data_length = len(data)
        packet_length = 16 + data_length  # Header is 16 bytes
        
        # Get values (fuzzed or normal)
        pkt_len = self.get_fuzz_value(fuzz_fields, "PacketLength", 4, "I")
        if pkt_len is None:
            pkt_len = packet_length
        
        cmd_type = self.get_fuzz_value(fuzz_fields, "CommandType", 2, "H")
        if cmd_type is None:
            cmd_type = command_type
        
        flags = self.get_fuzz_value(fuzz_fields, "Flags", 2, "H")
        if flags is None:
            flags = 0
        
        data_len = self.get_fuzz_value(fuzz_fields, "DataLength", 4, "I")
        if data_len is None:
            data_len = data_length
        
        # Check for fuzzed data
        fuzzed_data = self.get_fuzz_bytes(fuzz_fields, "Filename", len(data))
        if fuzzed_data is not None:
            data = fuzzed_data
        
        # Build the packet
        header = struct.pack("<I", 0x4F425731)      # Magic: "OBW1"
        header += struct.pack("<I", pkt_len)         # Packet length
        header += struct.pack("<H", cmd_type)        # Command type
        header += struct.pack("<H", flags)           # Flags
        header += struct.pack("<I", data_len)        # Data length
        
        return header + data
```

### Step 5: Implement the Fuzzing Session

```python
    def run_fuzzing_session(self):
        """
        Run one fuzzing iteration.
        
        This is called repeatedly by the framework.
        """
        # Connect if not connected
        if not self.sock:
            self.connect()
        
        # Prepare test data
        filename = b"test_file.txt"
        command_type = 1  # 1 = READ command
        
        # Decide what to fuzz based on settings
        fuzz_fields = {}
        
        if self.should_fuzz("header"):
            # Select random header fields to fuzz
            fuzz_fields = self.select_fuzz_fields("header")
        
        if self.should_fuzz("data"):
            # Add data field fuzzing
            data_fuzz = self.select_fuzz_fields("data")
            fuzz_fields.update(data_fuzz)
        
        # Build and send the packet
        packet = self.build_packet(command_type, filename, fuzz_fields)
        self.send_packet(packet, "READ")
        
        # Check the response
        response = self.receive_response()
        
        if response is None:
            print("[!] No response - possible crash?")
        elif len(response) < 4:
            print(f"[!] Short response: {len(response)} bytes")
        else:
            # Parse response (protocol-specific)
            status = struct.unpack("<I", response[:4])[0]
            print(f"[*] Response status: 0x{status:08x}")
```

### Step 6: Add Command-Line Interface

```python
    def add_protocol_arguments(self, parser):
        """Add protocol-specific command line arguments."""
        parser.add_argument('-s', '--server', required=True, help='Target server IP')
        parser.add_argument('-p', '--port', type=int, default=9999, help='Target port')
    
    def parse_arguments(self, args=None):
        """Parse command line arguments."""
        parsed = super().parse_arguments(args)
        self.host = parsed.server
        self.port = parsed.port
        return parsed


def main():
    print_banner()
    fuzzer = SimpleFuzzer("127.0.0.1", 9999)
    fuzzer.run()


if __name__ == "__main__":
    main()
```

### Complete Fuzzer File

Here's everything together:

```python
#!/usr/bin/env python3
"""
simple_fuzzer.py - Example OffByWon protocol fuzzer

Usage:
    # Basic fuzzing
    python simple_fuzzer.py -s 192.168.1.100 -p 9999 -f
    
    # Fuzz only header fields
    python simple_fuzzer.py -s 192.168.1.100 -p 9999 -f --fuzz-target header
    
    # Length mismatch testing
    python simple_fuzzer.py -s 192.168.1.100 -p 9999 -f --fuzz-len
    
    # Dry run (send clean packets to verify connectivity)
    python simple_fuzzer.py -s 192.168.1.100 -p 9999 --dry-run

"""

import socket
import struct
from offbywon import ProtocolFuzzer, FieldType, print_banner


class SimpleFuzzer(ProtocolFuzzer):
    
    def __init__(self, host="127.0.0.1", port=9999):
        super().__init__()
        self.host = host
        self.port = port
        self.sock = None
    
    def get_protocol_name(self):
        return "SimpleProtocol"
    
    def get_available_targets(self):
        return ["header", "data"]
    
    def define_fuzz_fields(self):
        self.field_definitions["header"] = {
            "PacketLength": (FieldType.LENGTH, 4),
            "CommandType": (FieldType.INT, 2),
            "Flags": (FieldType.INT, 2),
            "DataLength": (FieldType.LENGTH, 4),
        }
        self.field_definitions["data"] = {
            "Filename": (FieldType.STRING, None),
        }
    
    def add_protocol_arguments(self, parser):
        parser.add_argument('-s', '--server', required=True, help='Target server')
        parser.add_argument('-p', '--port', type=int, default=9999, help='Target port')
    
    def parse_arguments(self, args=None):
        parsed = super().parse_arguments(args)
        self.host = parsed.server
        self.port = parsed.port
        return parsed
    
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5.0)
        self.sock.connect((self.host, self.port))
    
    def disconnect(self):
        if self.sock:
            self.sock.close()
            self.sock = None
    
    def _send_packet_impl(self, data, packet_type):
        if not self.sock:
            self.connect()
        self.sock.sendall(data)
    
    def receive_response(self, size=4096):
        try:
            return self.sock.recv(size)
        except:
            return None
    
    def build_packet(self, command_type, data, fuzz_fields=None):
        fuzz_fields = fuzz_fields or {}
        
        data_length = len(data)
        packet_length = 16 + data_length
        
        pkt_len = self.get_fuzz_value(fuzz_fields, "PacketLength", 4, "I") or packet_length
        cmd_type = self.get_fuzz_value(fuzz_fields, "CommandType", 2, "H") or command_type
        flags = self.get_fuzz_value(fuzz_fields, "Flags", 2, "H") or 0
        data_len = self.get_fuzz_value(fuzz_fields, "DataLength", 4, "I") or data_length
        
        fuzzed_data = self.get_fuzz_bytes(fuzz_fields, "Filename", len(data))
        if fuzzed_data:
            data = fuzzed_data
        
        packet = struct.pack("<I", 0x4F425731)  # Magic
        packet += struct.pack("<I", pkt_len)
        packet += struct.pack("<H", cmd_type)
        packet += struct.pack("<H", flags)
        packet += struct.pack("<I", data_len)
        packet += data
        
        return packet
    
    def run_fuzzing_session(self):
        if not self.sock:
            self.connect()
        
        filename = b"test_file.txt"
        fuzz_fields = {}
        
        if self.should_fuzz("header"):
            fuzz_fields = self.select_fuzz_fields("header")
        
        if self.should_fuzz("data"):
            fuzz_fields.update(self.select_fuzz_fields("data"))
        
        packet = self.build_packet(1, filename, fuzz_fields)
        self.send_packet(packet, "READ")
        
        response = self.receive_response()
        if response is None:
            print("[!] No response - possible crash?")


def main():
    print_banner()
    fuzzer = SimpleFuzzer()
    fuzzer.run()


if __name__ == "__main__":
    main()
```

---

## Field Types Reference

### FieldType.STRING

For text data like filenames, paths, usernames. Fuzzing strategies:

| Strategy | Description | Example |
|----------|-------------|---------|
| format_string | Printf-style exploits | `%s%s%s%s%s%s%s%s%s%s` |
| long_string | Buffer overflow | `AAAA...` (10-2060 bytes) |
| path_traversal | Escape directories | `\\..\\..\\..\\..\\` |
| null_inject | Inject null bytes | `\x00` |
| empty_string | Zero-length string | `` |
| unicode | Encoding edge cases | BOM markers, invalid UTF-8 |
| special_char | Invalid characters | `/`, `\`, `:`, `*`, `?` |

### FieldType.INT

For numbers like flags, types, identifiers. Fuzzing strategies:

| Strategy | Description | Example (4-byte) |
|----------|-------------|-----------------|
| boundary | Edge values | 0, 1, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF |
| bitflip | Flip random bit | 0x00000001 → 0x00000003 |
| off_by_one | Add/subtract 1 | 100 → 99 or 101 |
| overflow | Maximum values | 0xFFFFFFFF, 0xFFFFFFFE |
| zero | Zero value | 0 |
| random | Random value | Any 32-bit value |

### FieldType.LENGTH

For size and count fields. These are critical for finding off-by-one bugs:

| Strategy | Description | Example |
|----------|-------------|---------|
| delta | Small +/- change | 4096 → 4097 or 4095 |
| zero | Zero length | 0 |
| max | Maximum value | 0xFFFFFFFF |

Delta modes available via `--fuzz-len-mode`:

| Mode | Deltas |
|------|--------|
| standard | -4, -3, -2, -1, +1, +2, +3, +4 |
| extended | -8 through +8 |
| boundary | -1, +1 only |
| power2 | -16, -8, -4, -2, -1, +1, +2, +4, +8, +16 |

### FieldType.OFFSET

For pointers/offsets to other data. Fuzzing strategies:

| Strategy | Description | Example |
|----------|-------------|---------|
| misaligned | Odd offset | 64 → 65, 67, 69 |
| negative_wrap | Large value | 0xFFFFFFF0 |
| zero_offset | Zero | 0 |
| past_end | Beyond buffer | 64 → 65535 |
| delta | Small change | +/-1 to +/-8 |

### FieldType.BYTES

For raw binary data:

| Strategy | Description |
|----------|-------------|
| bitflip | Flip random bit in random byte |
| truncate | Remove bytes from end |
| extend | Add bytes (null, 0xFF, 'A', 0xDEADBEEF) |
| fill | Replace all with same byte |
| empty | Zero-length |
| random | Random bytes |

### FieldType.ASN_DER

For ASN.1/DER encoded data (certificates, Kerberos tickets):

| Strategy | Description |
|----------|-------------|
| tag_mutate | Random tag byte |
| length_mutate | Random length byte |
| indefinite_length | Set length to 0x80 |
| long_length_overflow | 4-byte max length |
| tag_class | Change tag class bits |
| bitflip | Random bit flip |

### FieldType.ARRAY

For lists of items:

| Strategy | Description |
|----------|-------------|
| count_overflow | Count > actual items |
| count_underflow | Count < actual items |
| zero_count | Count = 0 with data present |
| large_count | Count = 0xFFFF with minimal data |
| count_delta | Small +/- to count |

---

## Fuzzing Modes

### Standard Field Fuzzing (`-f`)

Fuzzes protocol fields using type-appropriate strategies:

```bash
python my_fuzzer.py -s 192.168.1.100 -p 445 -f
```

### Targeted Fuzzing (`--fuzz-target`)

Only fuzz specific packet types or fields:

```bash
# Only fuzz NEGOTIATE packets
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-target negotiate

# Fuzz multiple targets
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-target negotiate --fuzz-target session
```

### Multi-Field Fuzzing (`--fuzz-count`)

Fuzz multiple fields per packet:

```bash
# Fuzz 3 fields at once
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-count 3
```

### Length Mismatch Testing (`--fuzz-len`)

Specifically tests length/count field mismatches:

```bash
# Standard deltas (+/-1 to +/-4)
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-len

# Only +/-1 (most likely to find real bugs)
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-len --fuzz-len-mode boundary

# Extended range
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --fuzz-len --fuzz-len-mode extended
```

### Blind Fuzzing (`--blind`)

Mutates packets without knowledge of structure:

```bash
python my_fuzzer.py -s 192.168.1.100 -p 445 --blind
```

Strategies include: bit flips, byte flips, known bad integers, random bytes, deletion, insertion.

### Byteflip Mode (`--byteflip`)

Replace one byte with a random one:

```bash
# Flip 5 random bytes per packet
python my_fuzzer.py -s 192.168.1.100 -p 445 --byteflip --fuzz-count 1
```

### Combined Mode (`--combined`)

Field fuzzing plus one random byte flip:

```bash
python my_fuzzer.py -s 192.168.1.100 -p 445 -f --combined
```

### DER/ASN.1 Bruteforce (`--ber-bruteforce`)

Systematically test every byte in ASN.1 structures:

```bash
# Test all 256 values at each position
python my_fuzzer.py -s 192.168.1.100 -p 88 --ber-bruteforce

# Test only boundary values (0x00, 0x7F, 0x80, 0xFF, etc.)
python my_fuzzer.py -s 192.168.1.100 -p 88 --ber-bruteforce --ber-boundary

# Strict mode (fewer false positives)
python my_fuzzer.py -s 192.168.1.100 -p 88 --ber-bruteforce --ber-strict
```

### Dry Run (`--dry-run`)

Send clean packets to verify connectivity before fuzzing:

```bash
python my_fuzzer.py -s 192.168.1.100 -p 445 --dry-run
```

---

## Command-Line Options

### Connection Options

| Option | Description |
|--------|-------------|
| `-s`, `--server` | Target server IP address |
| `-p`, `--port` | Target port number |

### Fuzzing Options

| Option | Description |
|--------|-------------|
| `-f`, `--fuzz` | Enable field-level fuzzing |
| `--fuzz-target TARGET` | Only fuzz specific targets (can repeat) |
| `--fuzz-count N` | Number of fields to fuzz per packet |
| `--fuzz-len` | Enable length/count mismatch testing |
| `--fuzz-len-mode MODE` | Delta mode: standard, extended, boundary, power2 |

### Mutation Modes

| Option | Description |
|--------|-------------|
| `--blind` | Blind packet mutation |
| `--byteflip` | Random byte replacement |
| `--combined` | Field fuzzing + bit flip |

### DER/ASN.1 Options

| Option | Description |
|--------|-------------|
| `--ber-bruteforce` | Systematically test ASN.1 positions |
| `--ber-boundary` | Only test boundary values |
| `--ber-strict` | Reduce false positives |
| `--ber-double` | Test two positions at once |

### Control Options

| Option | Description |
|--------|-------------|
| `--dry-run` | Send clean packets only |
| `-n`, `--num-iterations N` | Run N iterations then stop |
| `-v`, `--verbose` | Verbose output |

---

## Complete Example: Building a TCP Protocol Fuzzer

Here's a more complete example that shows all the features. This fuzzer is for a hypothetical file server protocol.

```python
#!/usr/bin/env python3
"""
file_server_fuzzer.py - OffByWon fuzzer for FileServer protocol

Protocol structure:
    
    REQUEST HEADER (20 bytes):
    ┌────────────────────────────────────────┐
    │ 0-3:   Magic (0x46494C45 = "FILE")     │
    │ 4-7:   Packet Length                   │
    │ 8-9:   Command (1=LIST, 2=GET, 3=PUT)  │
    │ 10-11: Flags                           │
    │ 12-15: Session ID                      │
    │ 16-19: Data Length                     │
    └────────────────────────────────────────┘
    
    DATA (variable):
    ┌────────────────────────────────────────┐
    │ Command-specific payload               │
    └────────────────────────────────────────┘

Usage:
    # Basic fuzzing
    python file_server_fuzzer.py -s 10.0.0.5 -p 2121 -f
    
    # Fuzz GET commands with length mismatches
    python file_server_fuzzer.py -s 10.0.0.5 -p 2121 -f --fuzz-target get --fuzz-len
    
    # Blind fuzzing all packet types
    python file_server_fuzzer.py -s 10.0.0.5 -p 2121 --blind

"""

import socket
import struct
import time
from offbywon import ProtocolFuzzer, FieldType, Fuzzer, print_banner


class FileServerFuzzer(ProtocolFuzzer):
    """Fuzzer for the FileServer protocol."""
    
    # Protocol constants
    MAGIC = 0x46494C45  # "FILE"
    
    CMD_LIST = 1
    CMD_GET = 2
    CMD_PUT = 3
    
    FLAG_COMPRESS = 0x0001
    FLAG_ENCRYPT = 0x0002
    
    def __init__(self):
        super().__init__()
        self.host = None
        self.port = None
        self.sock = None
        self.session_id = 0
        self.timeout = 5.0
    
    # ================================================================
    # Required ProtocolFuzzer methods
    # ================================================================
    
    def get_protocol_name(self):
        return "FileServer"
    
    def get_available_targets(self):
        return ["list", "get", "put", "header"]
    
    def define_fuzz_fields(self):
        """Define fuzzable fields for each packet type."""
        
        # Common header fields
        header_fields = {
            "PacketLength": (FieldType.LENGTH, 4),
            "Command": (FieldType.INT, 2),
            "Flags": (FieldType.INT, 2),
            "SessionID": (FieldType.INT, 4),
            "DataLength": (FieldType.LENGTH, 4),
        }
        
        self.field_definitions["header"] = header_fields
        
        # LIST command fields
        self.field_definitions["list"] = {
            **header_fields,
            "Path": (FieldType.STRING, None),
        }
        
        # GET command fields
        self.field_definitions["get"] = {
            **header_fields,
            "Filename": (FieldType.STRING, None),
            "Offset": (FieldType.OFFSET, 8),
            "ReadLength": (FieldType.LENGTH, 4),
        }
        
        # PUT command fields
        self.field_definitions["put"] = {
            **header_fields,
            "Filename": (FieldType.STRING, None),
            "FileSize": (FieldType.LENGTH, 8),
            "FileData": (FieldType.BYTES, None),
        }
    
    def add_protocol_arguments(self, parser):
        """Add FileServer-specific arguments."""
        parser.add_argument('-s', '--server', required=True,
                          help='Target server IP/hostname')
        parser.add_argument('-p', '--port', type=int, default=2121,
                          help='Target port (default: 2121)')
        parser.add_argument('--timeout', type=float, default=5.0,
                          help='Socket timeout in seconds (default: 5.0)')
        parser.add_argument('--session', type=int, default=0,
                          help='Session ID to use (default: 0)')
    
    def parse_arguments(self, args=None):
        parsed = super().parse_arguments(args)
        self.host = parsed.server
        self.port = parsed.port
        self.timeout = parsed.timeout
        self.session_id = parsed.session
        return parsed
    
    # ================================================================
    # Connection handling
    # ================================================================
    
    def connect(self):
        """Establish connection to server."""
        if self.sock:
            self.disconnect()
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        self.log(f"[*] Connected to {self.host}:{self.port}", "VERBOSE")
    
    def disconnect(self):
        """Close connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def _send_packet_impl(self, data, packet_type):
        """Send packet over socket."""
        if not self.sock:
            self.connect()
        self.sock.sendall(data)
    
    def receive_response(self, expected_size=None):
        """Receive response from server."""
        try:
            # First read the header
            header = self.sock.recv(20)
            if len(header) < 20:
                return header
            
            # Parse packet length
            packet_len = struct.unpack("<I", header[4:8])[0]
            
            # Read remaining data
            remaining = packet_len - 20
            data = header
            while remaining > 0:
                chunk = self.sock.recv(min(remaining, 4096))
                if not chunk:
                    break
                data += chunk
                remaining -= len(chunk)
            
            return data
            
        except socket.timeout:
            return None
        except Exception as e:
            self.log(f"[!] Receive error: {e}", "VERBOSE")
            return None
    
    # ================================================================
    # Packet building
    # ================================================================
    
    def build_header(self, command, data_length, fuzz_fields=None):
        """Build packet header."""
        fuzz_fields = fuzz_fields or {}
        
        packet_length = 20 + data_length
        
        # Apply fuzz values or use defaults
        pkt_len = self.get_fuzz_value(fuzz_fields, "PacketLength", 4, "I")
        if pkt_len is None:
            pkt_len = packet_length
        
        cmd = self.get_fuzz_value(fuzz_fields, "Command", 2, "H")
        if cmd is None:
            cmd = command
        
        flags = self.get_fuzz_value(fuzz_fields, "Flags", 2, "H")
        if flags is None:
            flags = 0
        
        sess_id = self.get_fuzz_value(fuzz_fields, "SessionID", 4, "I")
        if sess_id is None:
            sess_id = self.session_id
        
        data_len = self.get_fuzz_value(fuzz_fields, "DataLength", 4, "I")
        if data_len is None:
            data_len = data_length
        
        header = struct.pack("<I", self.MAGIC)
        header += struct.pack("<I", pkt_len)
        header += struct.pack("<H", cmd)
        header += struct.pack("<H", flags)
        header += struct.pack("<I", sess_id)
        header += struct.pack("<I", data_len)
        
        return header
    
    def build_list_packet(self, path, fuzz_fields=None):
        """Build a LIST command packet."""
        fuzz_fields = fuzz_fields or {}
        
        # Check for fuzzed path
        fuzzed_path = self.get_fuzz_bytes(fuzz_fields, "Path", len(path))
        if fuzzed_path:
            path = fuzzed_path
        
        # Path format: 2-byte length + path bytes
        path_data = struct.pack("<H", len(path)) + path
        
        header = self.build_header(self.CMD_LIST, len(path_data), fuzz_fields)
        return header + path_data
    
    def build_get_packet(self, filename, offset=0, read_length=4096, fuzz_fields=None):
        """Build a GET command packet."""
        fuzz_fields = fuzz_fields or {}
        
        # Check for fuzzed values
        fuzzed_filename = self.get_fuzz_bytes(fuzz_fields, "Filename", len(filename))
        if fuzzed_filename:
            filename = fuzzed_filename
        
        fuzzed_offset = self.get_fuzz_value(fuzz_fields, "Offset", 8, "Q")
        if fuzzed_offset is not None:
            offset = fuzzed_offset
        
        fuzzed_read_len = self.get_fuzz_value(fuzz_fields, "ReadLength", 4, "I")
        if fuzzed_read_len is not None:
            read_length = fuzzed_read_len
        
        # Data format: filename_len(2) + filename + offset(8) + read_length(4)
        data = struct.pack("<H", len(filename))
        data += filename
        data += struct.pack("<Q", offset)
        data += struct.pack("<I", read_length)
        
        header = self.build_header(self.CMD_GET, len(data), fuzz_fields)
        return header + data
    
    def build_put_packet(self, filename, file_data, fuzz_fields=None):
        """Build a PUT command packet."""
        fuzz_fields = fuzz_fields or {}
        
        # Check for fuzzed values
        fuzzed_filename = self.get_fuzz_bytes(fuzz_fields, "Filename", len(filename))
        if fuzzed_filename:
            filename = fuzzed_filename
        
        fuzzed_size = self.get_fuzz_value(fuzz_fields, "FileSize", 8, "Q")
        if fuzzed_size is not None:
            file_size = fuzzed_size
        else:
            file_size = len(file_data)
        
        fuzzed_data = self.get_fuzz_bytes(fuzz_fields, "FileData", len(file_data))
        if fuzzed_data:
            file_data = fuzzed_data
        
        # Data format: filename_len(2) + filename + file_size(8) + file_data
        data = struct.pack("<H", len(filename))
        data += filename
        data += struct.pack("<Q", file_size)
        data += file_data
        
        header = self.build_header(self.CMD_PUT, len(data), fuzz_fields)
        return header + data
    
    # ================================================================
    # Response parsing
    # ================================================================
    
    def parse_response(self, response):
        """Parse server response."""
        if not response or len(response) < 20:
            return {"status": "NO_RESPONSE", "error": True}
        
        try:
            magic = struct.unpack("<I", response[0:4])[0]
            pkt_len = struct.unpack("<I", response[4:8])[0]
            status = struct.unpack("<H", response[8:10])[0]
            
            result = {
                "magic": magic,
                "packet_length": pkt_len,
                "status": status,
                "error": status != 0,
            }
            
            if magic != self.MAGIC:
                result["warning"] = "Invalid magic number"
            
            return result
            
        except Exception as e:
            return {"status": "PARSE_ERROR", "error": True, "exception": str(e)}
    
    # ================================================================
    # Fuzzing session
    # ================================================================
    
    def run_fuzzing_session(self):
        """Run one iteration of fuzzing."""
        
        # Ensure connection
        if not self.sock:
            self.connect()
        
        # Pick a command to send
        from random import choice
        commands = ["list", "get", "put"]
        command = choice(commands)
        
        # Get fuzz fields if enabled
        fuzz_fields = {}
        target = command
        
        if self.should_fuzz(target):
            fuzz_fields = self.select_fuzz_fields(target)
        elif self.should_fuzz("header"):
            fuzz_fields = self.select_fuzz_fields("header")
        
        # Build the packet
        if command == "list":
            packet = self.build_list_packet(b"/home/user", fuzz_fields)
        elif command == "get":
            packet = self.build_get_packet(b"test.txt", 0, 4096, fuzz_fields)
        else:  # put
            packet = self.build_put_packet(b"upload.txt", b"Hello World!", fuzz_fields)
        
        # Send and receive
        try:
            self.send_packet(packet, command.upper())
            response = self.receive_response()
            
            if response:
                parsed = self.parse_response(response)
                status_str = f"0x{parsed['status']:04x}" if isinstance(parsed['status'], int) else parsed['status']
                self.log(f"[*] Response: status={status_str}", "ALWAYS")
                
                if parsed.get("warning"):
                    self.log(f"[!] Warning: {parsed['warning']}", "ALWAYS")
            else:
                self.log("[!] No response received", "ALWAYS")
                # Reconnect for next iteration
                self.disconnect()
                
        except Exception as e:
            self.log(f"[!] Error: {e}", "ALWAYS")
            self.disconnect()
    
    # ================================================================
    # DER/BER support (for protocols using ASN.1)
    # ================================================================
    
    def build_ber_packet(self):
        """Build a packet for BER bruteforce mode."""
        # Return a clean packet that contains ASN.1 data
        # This would be used for protocols like LDAP, Kerberos, etc.
        raise NotImplementedError("This protocol doesn't use ASN.1")
    
    def send_ber_packet(self, data):
        """Send packet for BER testing."""
        self._send_packet_impl(data, "BER_TEST")
    
    def receive_ber_response(self):
        """Receive response during BER testing."""
        return self.receive_response()
    
    def reconnect_ber(self):
        """Reconnect during BER testing."""
        self.disconnect()
        time.sleep(0.1)
        self.connect()


def main():
    print_banner()
    fuzzer = FileServerFuzzer()
    fuzzer.run()


if __name__ == "__main__":
    main()
```

---

## Array Overflow Testing

Many protocols include arrays: a count field followed by multiple elements. These are good targets:

- **Count > Elements (overflow)**
- **Count < Elements (underflow)**
- **Count = MAX, Elements = 1**
- **Count = 0, Elements present**

### Using ArrayFuzzer

```python
from offbywon import ArrayFuzzer
import struct

# Step 1: Define how to build ONE element (protocol-specific)
def build_smb2_nego_context(ctx_type, ctx_data):
    """Build one SMB2 Negotiate Context."""
    data_len = len(ctx_data)
    header = struct.pack('<HHI', ctx_type, data_len, 0)
    padding = (8 - (len(header) + data_len) % 8) % 8
    return header + ctx_data + (b'\x00' * padding)

# Step 2: Create the ArrayFuzzer
array_fuzz = ArrayFuzzer(
    count_size=2,                        # Count is 2 bytes (USHORT)
    element_builder=build_smb2_nego_context,
)

# Step 3: Add normal elements
array_fuzz.add_element(0x0001, b'\x01\x00\x26\x00' + b'\x00' * 32)
array_fuzz.add_element(0x0002, b'\x01\x00' + b'\x02\x00\x04\x00')

# Step 4: Get fuzzed arrays
count_bytes, data_bytes, description = array_fuzz.fuzz()
print(f"Test: {description}")
# Output: "Test: count_overflow (count=18, actual=2, +16)"
```

### Fuzzing Strategies

| Strategy | What it Does | Bug Type |
|----------|--------------|----------|
| `count_overflow` | Count > actual items | OOB read, heap overflow |
| `count_underflow` | Count < actual items | Logic bugs, data ignored |
| `zero_count` | Count = 0 with data present | Null deref, uninit state |
| `huge_count` | Count = 0xFFFF with minimal data | Integer overflow |
| `count_delta` | Small +/-1-4 changes | Off-by-one errors |
| `duplicate` | Duplicate elements | Double-free, logic bugs |
| `integer_overflow` | count * elem_size > 0xFFFFFFFF | Allocation overflow |

### Generating All Test Cases

```python
# Iterate through all interesting test cases
for count_bytes, data_bytes, desc in array_fuzz.generate_test_cases():
    packet = build_packet_header() + count_bytes + data_bytes
    send_packet(packet)
    
    if is_interesting(response):
        print(f"[!] Interesting: {desc}")
```

---

## DER/ASN.1 Fuzzing

Many protocols use ASN.1/DER encoding (Kerberos, LDAP, TLS, SNMP), OffByWon has special support for finding bugs in ASN.1 parsers.

### Understanding ASN.1/DER

ASN.1 data has a consistent format:

```
┌─────────────┬─────────────┬─────────────────┐
│ Tag (1+ B)  │ Length (1+B)│ Value (N bytes) │
└─────────────┴─────────────┴─────────────────┘
```

**Tag byte** tells you what type of data:
- 0x02 = INTEGER
- 0x04 = OCTET STRING
- 0x30 = SEQUENCE (like a struct)
- 0x06 = OID (object identifier)
- 0xA0-0xAF = Context-specific tags

**Length byte** tells you how many bytes follow:
- 0x00-0x7F = That many bytes (short form)
- 0x80 = Indefinite length
- 0x81-0x84 = Next 1-4 bytes contain length (long form)

### Using DERScanner

```python
from offbywon import DERScanner

# Scan for ASN.1 structures
scanner = DERScanner(strict=False)
positions = scanner.scan(packet_bytes)

for offset, pos_type, description in positions:
    print(f"[{offset:4d}] {pos_type}: {description}")

# Output:
# [   0] TAG: SEQUENCE/C (0x30)
# [   1] LENGTH: len=45 (0x2d)
# [   2] TAG: INTEGER (0x02)
# [   3] LENGTH: len=1 (0x01)
# ...
```

### Implementing BER Fuzzing in Your Fuzzer

```python
class KerberosFuzzer(ProtocolFuzzer):
    
    def build_ber_packet(self):
        """Build a Kerberos AS-REQ packet."""
        # Build your ASN.1 packet here
        return self.build_as_req()
    
    def send_ber_packet(self, data):
        """Send to KDC."""
        self.sock.sendall(data)
    
    def receive_ber_response(self):
        """Receive KDC response."""
        return self.sock.recv(4096)
    
    def reconnect_ber(self):
        """Reconnect to KDC."""
        self.disconnect()
        self.connect()
    
    def parse_ber_response(self, response):
        """Parse Kerberos response for status."""
        if not response:
            return {'status': 'NO_RESPONSE'}
        
        # Parse the error code from AS-REP or KRB-ERROR
        try:
            # ... parsing code ...
            return {'status': f'KRB_{error_code}'}
        except:
            return {'status': 'PARSE_ERROR'}
```

Run BER bruteforce:

```bash
# Test all positions with all values (slow but thorough)
python kerberos_fuzzer.py -s dc.domain.local -p 88 --ber-bruteforce

# Test only boundary values (faster)
python kerberos_fuzzer.py -s dc.domain.local -p 88 --ber-bruteforce --ber-boundary

# Reduce false positives
python kerberos_fuzzer.py -s dc.domain.local -p 88 --ber-bruteforce --ber-strict
```

---

## API Reference

### FieldType

Field type constants:

```python
FieldType.STRING   # Text/string data
FieldType.INT      # Integer/number
FieldType.LENGTH   # Length/size/count field
FieldType.OFFSET   # Pointer/offset
FieldType.BYTES    # Raw bytes
FieldType.ASN_DER  # ASN.1/DER encoded
FieldType.ARRAY    # Array of items
```

### Fuzzer

```python
fuzzer = Fuzzer(mode='standard')  # 'standard', 'extended', 'boundary', 'power2'

# Fuzz a field
fuzzed_bytes, description = fuzzer.fuzz(field_type, original, size=None)

# Select and fuzz fields from a dictionary
fuzz_values, info_str = fuzzer.select_fields(
    available_fields,    # dict: name -> (FieldType, size)
    num_fields=1,        # how many to fuzz
    length_only=False,   # only LENGTH fields?
    original_values=None # dict: name -> original value
)
```

### PacketBuilder

```python
builder = PacketBuilder("PacketName")

# Add fields
builder.add_field(name, field_type, size=None, default=None, pack_fmt=None)
builder.add_int(name, size, default=0)
builder.add_length(name, size, default=0)
builder.add_string(name, default=b"")
builder.add_bytes(name, size=None, default=b"")

# Set fuzzing mode
builder.set_mode('extended')

# Build packets
packet = builder.build(values=None)
packet, fuzz_info = builder.build_fuzzed(
    fuzz_fields=None,    # specific fields to fuzz
    fuzz_types=None,     # types to target
    num_fields=1,        # how many
    values=None          # override values
)
```

### Mutator

```python
mutator = Mutator(skip_header=4)

# Random mutation
mutated, info = mutator.mutate(data, mutation_type=None)

# Specific mutation
mutated, info = mutator.mutate(data, MutationType.BIT_FLIP)

# Byteflip
mutated, info = mutator.byteflip(data, count=3)
```

### LengthDeltaGenerator

```python
gen = LengthDeltaGenerator(mode='standard')

# Get deltas
deltas = gen.get_deltas()  # [-4, -3, -2, -1, +1, +2, +3, +4]

# Generate test cases
cases = gen.generate_test_cases(base_count=10, item_size=2)
# Returns: [(type, count_delta, length_delta, description), ...]

# Apply delta with bounds
value = gen.apply_delta(original, delta, min_val=0, max_val=0xFFFF)
```

### DERScanner

```python
scanner = DERScanner(strict=False, max_depth=32)

# Scan for structures
positions = scanner.scan(data, start_offset=0)
# Returns: [(offset, type, description), ...]

# Get fuzzable positions (for bruteforce)
fuzz_positions = scanner.get_fuzzable_positions(data)
# Returns: [(offset, description), ...]

# Get structure summary
structures = scanner.get_structure_summary(data)
# Returns: [{'offset':, 'tag':, 'tag_name':, 'total_size':, ...}, ...]

# Parse individual elements
is_valid, tag_bytes, length, length_bytes = scanner.is_valid_structure(data, offset)
tag_number, bytes_consumed = scanner.parse_long_tag(data, offset)
length, bytes_consumed = scanner.parse_length(data, offset)
oid_string = scanner.decode_oid(oid_bytes)
```

### ArrayFuzzer

```python
from offbywon import ArrayFuzzer

# Initialize
array_fuzz = ArrayFuzzer(
    count_size=2,           # Size of count field (1, 2, or 4 bytes)
    element_builder=None,   # Optional function to build elements
    count_signed=False      # Whether count is signed
)

# Add elements
array_fuzz.add_element(*args, **kwargs)  # Uses element_builder
array_fuzz.add_raw_element(element_bytes) # Add pre-built bytes
array_fuzz.clear_elements()

# Build arrays
count, data, desc = array_fuzz.build_normal()  # Correct count
count, data, desc = array_fuzz.fuzz()          # Random strategy
count, data, desc = array_fuzz.fuzz(ArrayFuzzer.STRATEGY_COUNT_OVERFLOW)

# Generate all test cases
for count, data, desc in array_fuzz.generate_test_cases():
    send(header + count + data)
```

### ProtocolFuzzer

Base class methods to implement:

```python
class MyFuzzer(ProtocolFuzzer):
    # REQUIRED
    def get_protocol_name(self): ...
    def get_available_targets(self): ...
    def define_fuzz_fields(self): ...
    def run_fuzzing_session(self): ...
    def _send_packet_impl(self, data, packet_type): ...
    
    # OPTIONAL (for CLI)
    def add_protocol_arguments(self, parser): ...
    
    # OPTIONAL (for BER bruteforce)
    def build_ber_packet(self): ...
    def send_ber_packet(self, data): ...
    def receive_ber_response(self): ...
    def reconnect_ber(self): ...
    def parse_ber_response(self, response): ...
```

### Helper methods available:

```python
# Check if fuzzing is enabled for target
self.should_fuzz(target)

# Select fields to fuzz
fuzz_values = self.select_fuzz_fields(target)

# Get fuzz value (returns None if not fuzzed)
value = self.get_fuzz_value(fuzz_fields, field_name, size, fmt)

# Get fuzz bytes (returns None if not fuzzed)  
data = self.get_fuzz_bytes(fuzz_fields, field_name, size)

# Send packet (applies blind/byteflip/combined if enabled)
self.send_packet(data, packet_type)

# Length field helpers
deltas = self.get_length_deltas()
cases = self.generate_length_test_cases(base_count, item_size)
value = self.apply_length_delta(value, delta, min_val, max_val)

# Logging
self.log(message, level)  # "ALWAYS", "INFO", "VERBOSE"
```

---

## Tips for Effective Fuzzing

1. **Start with dry run**: Always verify the correctness of your implementation first with `--dry-run`

2. **Mix Structured with Chaos**: Great way to find bugs `--combined`

3. **Understand What You Fuzz**: First step is to understand the protocol you want to fuzz.

4. **Monitor the server**: Run the target with a debugger attached (gdb, WinDbg) to catch crashes.


