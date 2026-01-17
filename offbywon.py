#!/usr/bin/env python3
"""
OffByWon Fuzzing Framework
===========================

A protocol fuzzing framework designed to find bugs others miss.

Core Philosophy:
- Off-by-one around REAL boundaries (allocator chunks, page sizes)
- Integer overflow triggers (size * element_size)  
- Odd/prime sizes that bypass aligned-only testing
- Signed/unsigned confusion values
- Misaligned sizes that break assumptions
- Length/count field mismatches

Features:
- Simple packet building with automatic fuzzing by field type
- Field types: STRING, INT, LENGTH, ASN_DER, ARRAY, BYTES
- Each type has targeted fuzzing strategies
- Clear output: hex dump, field name, original → fuzzed value

OffByWon Fuzzing Framework
Author: Laurent Gaffié
Website: https://secorizon.com
Twitter: @secorizon
"""

import struct
import socket
import argparse
import sys
import errno
import time
from random import choice, randint, getrandbits, sample


# =============================================================================
# FRAMEWORK VERSION
# =============================================================================

__version__ = "1.0.0"
__framework__ = "OffByWon"
__author__ = "Laurent Gaffié"
__website__ = "https://secorizon.com"
__twitter__ = "@secorizon"

# Public API exports
__all__ = [
    # Core classes
    'FieldType',
    'Fuzzer',
    'Mutator',
    'MutationType',
    'OverflowGenerator',
    'PacketPrinter',
    # Packet building
    'PacketField',
    'PacketBuilder',
    # Utilities
    'LengthDeltaGenerator',
    'DERScanner',
    'ArrayFuzzer',
    'ProtocolFuzzer',
    # Helpers
    'print_banner',
]


# =============================================================================
# FIELD TYPES - Define what kind of data each field contains
# =============================================================================

class FieldType:
    """Field type constants for packet definition."""
    STRING = 'string'      # Strings: format strings, long strings, paths, unicode
    INT = 'int'            # Integers: overflow, boundary, signed/unsigned
    LENGTH = 'length'      # Length fields: delta +/-1, null, max
    ASN_DER = 'asn_der'    # ASN.1/DER: tag/length byte mutations
    ARRAY = 'array'        # Arrays: count + items overflow
    BYTES = 'bytes'        # Raw bytes: bit flips, truncation
    OFFSET = 'offset'      # Offset fields: misalignment, out of bounds


# =============================================================================
# FUZZER - Unified fuzzing engine for all field types
# =============================================================================

class Fuzzer:
    """
    Unified fuzzing engine for all field types.
    
    Usage:
        fuzzer = Fuzzer(mode='extended')
        value, desc = fuzzer.fuzz(FieldType.LENGTH, original=4096, size=4)
        value, desc = fuzzer.fuzz(FieldType.STRING, original=b"test.txt", size=None)
        value, desc = fuzzer.fuzz(FieldType.INT, original=0, size=4)
    """
    
    # Delta values for LENGTH fields
    DELTAS = {
        'standard': [-4, -3, -2, -1, +1, +2, +3, +4],
        'extended': [-8, -7, -6, -5, -4, -3, -2, -1, +1, +2, +3, +4, +5, +6, +7, +8],
        'boundary': [-1, +1],
        'power2': [-16, -8, -4, -2, -1, +1, +2, +4, +8, +16],
    }
    
    # Interesting integer boundaries
    INT_BOUNDARIES = {
        1: [0x00, 0x01, 0x7e, 0x7f, 0x80, 0x81, 0xfe, 0xff],
        2: [0x0000, 0x0001, 0x00ff, 0x0100, 0x7fff, 0x8000, 0xfffe, 0xffff],
        4: [0x00000000, 0x00000001, 0x0000ffff, 0x00010000, 
            0x7fffffff, 0x80000000, 0xfffffffe, 0xffffffff],
        8: [0x0000000000000000, 0x00000000ffffffff, 0x0000000100000000,
            0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff],
    }
    
    # Format string attacks
    FORMAT_STRINGS = [
        b"%s%s%s%s%s%s%s%s%s%s",
        b"%n%n%n%n%n%n%n%n%n%n",
        b"%x%x%x%x%x%x%x%x%x%x",
        b"%.16705u%2\\$hn",
        b"%p%p%p%p%p%p%p%p%p%p",
        b"AAAA%08x.%08x.%08x.%08x",
    ]
    
    # Path traversal patterns (base patterns - multiplied at runtime)
    PATH_PATTERNS = [
        b"\\..\\..",          # Windows UNC traversal
        b"\\..\\",            # Windows backslash traversal  
        b"AA/AA/",            # Forward slash padding
        b"..\\",              # Simple Windows traversal
        b"../",               # Simple Unix traversal
        b"....//",            # Double-dot double-slash
        b"..../\\",           # Mixed traversal
    ]
    
    # Windows reserved names (cause issues in file operations)
    RESERVED_NAMES = [b"CON", b"PRN", b"AUX", b"NUL", b"COM1", b"COM2", b"LPT1", b"LPT2"]
    
    # Special path targets
    PATH_TARGETS = [
        b"\\windows\\system32\\config\\sam",
        b"\\windows\\system32\\drivers\\etc\\hosts",
        b"etc\\passwd",
        b"etc\\shadow",
    ]
    
    def __init__(self, mode='standard'):
        """
        Initialize fuzzer.
        
        Args:
            mode: 'standard', 'extended', 'boundary', or 'power2'
        """
        self.mode = mode
        self.deltas = self.DELTAS.get(mode, self.DELTAS['standard'])
    
    def fuzz(self, field_type, original, size=None):
        """
        Fuzz a field based on its type.
        
        Args:
            field_type: FieldType constant (STRING, INT, LENGTH, etc.)
            original: Original value (bytes for STRING/BYTES, int for INT/LENGTH)
            size: Field size in bytes (required for INT/LENGTH, optional for others)
            
        Returns:
            Tuple of (fuzzed_bytes, description_string)
        """
        if field_type == FieldType.STRING:
            return self._fuzz_string(original)
        elif field_type == FieldType.INT:
            return self._fuzz_int(original, size or 4)
        elif field_type == FieldType.LENGTH:
            return self._fuzz_length(original, size or 4)
        elif field_type == FieldType.ASN_DER:
            return self._fuzz_asn_der(original)
        elif field_type == FieldType.ARRAY:
            return self._fuzz_array(original, size)
        elif field_type == FieldType.BYTES:
            return self._fuzz_bytes(original)
        elif field_type == FieldType.OFFSET:
            return self._fuzz_offset(original, size or 4)
        else:
            # Unknown type - do random bytes
            return self._fuzz_bytes(original)
    
    def _fuzz_string(self, original):
        """Fuzz string fields: format strings, long strings, paths, unicode."""
        strategy = randint(0, 7)
        
        if strategy == 0:
            # Format string attack
            fuzzed = choice(self.FORMAT_STRINGS)
            return fuzzed, f"format_string ({fuzzed[:20]}...)"
        
        elif strategy == 1:
            # Long string (buffer overflow) - use random lengths to hit edge cases
            length = randint(10, 2060)  # Random length catches off-by-one at non-standard sizes
            fuzzed = b"A" * length
            return fuzzed, f"long_string (A*{length})"
        
        elif strategy == 2:
            # Path traversal - dynamic with random repetitions
            pattern = choice(self.PATH_PATTERNS)
            reps = randint(1, 120)
            fuzzed = pattern * reps
            # Optionally append a target
            if randint(0, 2) == 0:
                fuzzed += choice(self.PATH_TARGETS)
            return fuzzed, f"path_traversal ({len(fuzzed)} bytes, {reps} reps)"
        
        elif strategy == 3:
            # Null bytes injection
            if isinstance(original, bytes) and len(original) > 2:
                pos = randint(1, len(original) - 1)
                fuzzed = original[:pos] + b"\x00" + original[pos:]
                return fuzzed, f"null_inject (pos={pos})"
            else:
                fuzzed = b"\x00" * randint(1, 16)
                return fuzzed, "null_bytes"
        
        elif strategy == 4:
            # Empty string
            return b"", "empty_string"
        
        elif strategy == 5:
            # Unicode/encoding edge cases
            fuzzed = choice([
                b"\xff\xfe",  # UTF-16 LE BOM
                b"\xfe\xff",  # UTF-16 BE BOM
                b"\xef\xbb\xbf",  # UTF-8 BOM
                b"\x00\x00\x00\x00",  # Null chars
                b"\xff" * randint(1, 32),  # Invalid UTF-8
                "A\u0000B\u0000C".encode('utf-16-le'),  # Embedded nulls
            ])
            return fuzzed, f"unicode ({fuzzed[:8].hex()})"
        
        elif strategy == 6:
            # Windows reserved names or special chars
            if randint(0, 1) == 0:
                fuzzed = choice(self.RESERVED_NAMES)
                return fuzzed, f"reserved_name ({fuzzed.decode()})"
            else:
                fuzzed = choice([b"/", b"\\", b":", b"*", b"?", b'"', b"<", b">", b"|"])
                return fuzzed, f"special_char ({fuzzed})"
        
        else:
            # Random length string
            length = randint(1, 256)
            fuzzed = bytes([randint(0x20, 0x7e) for _ in range(length)])
            return fuzzed, f"random_string (len={length})"
    
    def _fuzz_int(self, original, size):
        """Fuzz integer fields: boundary values, overflow, bit flips."""
        strategy = randint(0, 5)
        max_val = (1 << (size * 8)) - 1
        
        if strategy == 0:
            # Boundary value
            boundaries = self.INT_BOUNDARIES.get(size, self.INT_BOUNDARIES[4])
            fuzzed = choice(boundaries)
            desc = f"boundary (0x{fuzzed:x})"
        
        elif strategy == 1:
            # Bit flip on original
            if original == 0:
                original = randint(1, max_val)
            bit_pos = randint(0, size * 8 - 1)
            fuzzed = original ^ (1 << bit_pos)
            desc = f"bitflip (bit {bit_pos})"
        
        elif strategy == 2:
            # Off-by-one from original
            delta = choice([-1, +1])
            fuzzed = max(0, min(original + delta, max_val))
            desc = f"off_by_one ({'+' if delta > 0 else ''}{delta})"
        
        elif strategy == 3:
            # Integer overflow trigger
            fuzzed = choice([max_val, max_val - 1, (max_val >> 1) + 1])
            desc = f"overflow (0x{fuzzed:x})"
        
        elif strategy == 4:
            # Zero
            fuzzed = 0
            desc = "zero"
        
        else:
            # Random value
            fuzzed = randint(0, max_val)
            desc = f"random (0x{fuzzed:x})"
        
        fuzzed = fuzzed & max_val
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(size, '<I')
        return struct.pack(fmt, fuzzed), desc
    
    def _fuzz_length(self, original, size):
        """Fuzz length fields: deltas, null, max."""
        strategy = randint(0, 4)
        max_val = (1 << (size * 8)) - 1
        
        if strategy <= 2:
            # Delta from original (most common for length fields)
            delta = choice(self.deltas)
            fuzzed = max(0, original + delta) & max_val
            delta_str = f"+{delta}" if delta > 0 else str(delta)
            desc = f"length_delta ({delta_str})"
        
        elif strategy == 3:
            # Zero length
            fuzzed = 0
            desc = f"zero_length"
        
        else:
            # Max value
            fuzzed = max_val
            desc = f"max_length (0x{fuzzed:x})"
        
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(size, '<I')
        return struct.pack(fmt, fuzzed), desc
    
    def _fuzz_offset(self, original, size):
        """Fuzz offset fields: misalignment, out of bounds."""
        strategy = randint(0, 4)
        max_val = (1 << (size * 8)) - 1
        
        if strategy == 0:
            # Misaligned (odd offset)
            fuzzed = original + choice([1, 3, 5, 7])
            desc = f"misaligned"
        
        elif strategy == 1:
            # Negative wrap (large value)
            fuzzed = max_val - randint(0, 16)
            desc = f"negative_wrap (0x{fuzzed:x})"
        
        elif strategy == 2:
            # Zero offset
            fuzzed = 0
            desc = "zero_offset"
        
        elif strategy == 3:
            # Point past end
            fuzzed = original + randint(1000, 65535)
            desc = f"past_end"
        
        else:
            # Small delta
            delta = choice(self.deltas)
            fuzzed = max(0, original + delta) & max_val
            desc = f"small_delta"
        
        fuzzed = fuzzed & max_val
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(size, '<I')
        return struct.pack(fmt, fuzzed), desc
    
    def _fuzz_asn_der(self, original):
        """Fuzz ASN.1/DER: tag and length byte mutations."""
        if not isinstance(original, bytes) or len(original) < 2:
            original = b"\x30\x00"  # Empty SEQUENCE
        
        strategy = randint(0, 5)
        fuzzed = bytearray(original)
        
        if strategy == 0:
            # Mutate tag byte
            fuzzed[0] = randint(0, 255)
            desc = f"tag_mutate (0x{fuzzed[0]:02x})"
        
        elif strategy == 1:
            # Mutate length byte
            if len(fuzzed) > 1:
                fuzzed[1] = randint(0, 255)
                desc = f"length_mutate (0x{fuzzed[1]:02x})"
            else:
                desc = "unchanged"
        
        elif strategy == 2:
            # Indefinite length (0x80)
            if len(fuzzed) > 1:
                fuzzed[1] = 0x80
                desc = "indefinite_length"
            else:
                desc = "unchanged"
        
        elif strategy == 3:
            # Long form length overflow
            if len(fuzzed) > 1:
                fuzzed[1] = 0x84  # 4-byte length follows
                fuzzed[2:2] = bytes([0xff, 0xff, 0xff, 0xff])
                desc = "long_length_overflow"
            else:
                desc = "unchanged"
        
        elif strategy == 4:
            # Universal tag manipulation
            fuzzed[0] = (fuzzed[0] & 0x1f) | choice([0x00, 0x40, 0x80, 0xc0])
            desc = f"tag_class (0x{fuzzed[0]:02x})"
        
        else:
            # Random byte flip
            pos = randint(0, len(fuzzed) - 1)
            fuzzed[pos] ^= (1 << randint(0, 7))
            desc = f"bitflip (pos={pos})"
        
        return bytes(fuzzed), desc
    
    def _fuzz_array(self, original, item_size):
        """Fuzz arrays: count/length mismatch, overflow."""
        # original should be (count, data_bytes) tuple or just data
        if isinstance(original, tuple):
            count, data = original
        else:
            data = original if isinstance(original, bytes) else b""
            count = len(data) // (item_size or 1) if item_size else 0
        
        strategy = randint(0, 4)
        
        if strategy == 0:
            # Count says more than data
            new_count = count + choice([1, 2, 4, 8, 16])
            desc = f"count_overflow (count={new_count}, actual={count})"
            return (new_count, data), desc
        
        elif strategy == 1:
            # Count says less than data
            new_count = max(0, count - choice([1, 2]))
            desc = f"count_underflow (count={new_count}, actual={count})"
            return (new_count, data), desc
        
        elif strategy == 2:
            # Zero count with data
            desc = f"zero_count (data_len={len(data)})"
            return (0, data), desc
        
        elif strategy == 3:
            # Large count, small data
            new_count = choice([0xff, 0xffff, 0x7fff])
            desc = f"large_count ({new_count})"
            return (new_count, data[:item_size] if item_size else data), desc
        
        else:
            # Normal delta
            delta = choice(self.deltas)
            new_count = max(0, count + delta)
            desc = f"count_delta ({'+' if delta > 0 else ''}{delta})"
            return (new_count, data), desc
    
    def _fuzz_bytes(self, original):
        """Fuzz raw bytes: bit flips, truncation, extension."""
        if not isinstance(original, bytes):
            original = b"\x00" * 4
        
        strategy = randint(0, 5)
        
        if strategy == 0 and len(original) > 0:
            # Bit flip
            fuzzed = bytearray(original)
            pos = randint(0, len(fuzzed) - 1)
            bit = randint(0, 7)
            fuzzed[pos] ^= (1 << bit)
            desc = f"bitflip (byte={pos}, bit={bit})"
            return bytes(fuzzed), desc
        
        elif strategy == 1 and len(original) > 1:
            # Truncate
            new_len = randint(1, len(original) - 1)
            desc = f"truncate ({len(original)} -> {new_len})"
            return original[:new_len], desc
        
        elif strategy == 2:
            # Extend with pattern
            pattern = choice([b"\x00", b"\xff", b"\x41", b"\xde\xad\xbe\xef"])
            extend_len = randint(1, 64)
            fuzzed = original + (pattern * extend_len)[:extend_len]
            desc = f"extend (+{extend_len} bytes)"
            return fuzzed, desc
        
        elif strategy == 3:
            # All same byte
            byte_val = choice([0x00, 0xff, 0x41, 0x90])
            fuzzed = bytes([byte_val] * len(original)) if original else bytes([byte_val] * 4)
            desc = f"fill (0x{byte_val:02x})"
            return fuzzed, desc
        
        elif strategy == 4:
            # Empty
            return b"", "empty"
        
        else:
            # Random bytes
            fuzzed = bytes([randint(0, 255) for _ in range(len(original) or 4)])
            desc = f"random ({len(fuzzed)} bytes)"
            return fuzzed, desc
    
    def select_fields(self, available_fields, num_fields=1, length_only=False, original_values=None):
        """
        Select and fuzz fields from available field definitions.
        
        This is the main entry point for field-based fuzzing. It handles:
        - Normal fuzzing: random field selection
        - Length-only fuzzing (--fuzz-len): only LENGTH type fields
        - Respects num_fields count for both modes
        
        Args:
            available_fields: dict of field_name -> (FieldType, size)
                Example: {"Length": (FieldType.LENGTH, 4), "Flags": (FieldType.INT, 2)}
            num_fields: number of fields to fuzz (default 1)
            length_only: if True, only fuzz LENGTH type fields (--fuzz-len mode)
            original_values: dict of field_name -> original_value for accurate fuzzing
            
        Returns:
            tuple: (fuzz_values, fuzz_lambdas, fuzz_info_str)
                - fuzz_values: dict of field_name -> fuzz_bytes
                - fuzz_lambdas: dict of field_name -> lambda (for get_fuzz_value compatibility)
                - fuzz_info_str: human-readable string of what was fuzzed
        """
        fuzz_values = {}
        fuzz_info = []
        original_values = original_values or {}
        
        # Build candidate list
        if length_only:
            # Only LENGTH type fields
            candidates = []
            for field_name, field_def in available_fields.items():
                if isinstance(field_def, tuple) and len(field_def) >= 2:
                    field_type, field_size = field_def[0], field_def[1]
                    if field_type == FieldType.LENGTH:
                        candidates.append((field_name, field_type, field_size))
                # Legacy: detect by name pattern
                elif self._is_length_field_name(field_name):
                    field_size = 4  # default
                    candidates.append((field_name, FieldType.LENGTH, field_size))
        else:
            # All fields
            candidates = []
            for field_name, field_def in available_fields.items():
                if isinstance(field_def, tuple) and len(field_def) >= 2:
                    field_type, field_size = field_def[0], field_def[1]
                    candidates.append((field_name, field_type, field_size))
                else:
                    # Legacy callable - treat as INT
                    candidates.append((field_name, field_def, None))
        
        if not candidates:
            return {}, {}, None
        
        # Select num_fields random candidates
        num_to_fuzz = min(num_fields, len(candidates))
        selected = sample(candidates, num_to_fuzz)
        
        # Fuzz each selected field
        for field_name, field_type, field_size in selected:
            original = original_values.get(field_name, 0)
            
            if isinstance(field_type, str) or hasattr(field_type, '__class__') and field_type in (
                FieldType.STRING, FieldType.INT, FieldType.LENGTH, 
                FieldType.OFFSET, FieldType.BYTES, FieldType.ASN_DER
            ):
                # New format with FieldType
                fuzz_bytes, desc = self.fuzz(field_type, original, field_size)
            else:
                # Unsupported field definition
                raise ValueError(f"Field '{field_name}' has invalid definition: {field_type}")
            
            fuzz_values[field_name] = fuzz_bytes
            fuzz_info.append((field_name, original, fuzz_bytes, desc))
        
        # Build info string
        fuzz_info_str = None
        if fuzz_info:
            parts = [f"{name}: {desc}" for name, orig, fuzz_bytes, desc in fuzz_info]
            fuzz_info_str = "; ".join(parts)
        
        return fuzz_values, fuzz_info_str
    
    def _is_length_field_name(self, name):
        """Check if field name suggests a length field (legacy support)."""
        name_lower = name.lower()
        length_indicators = ['length', 'size', 'count', 'len']
        offset_indicators = ['offset', 'ptr', 'pointer']
        
        # It's a length field if it has length indicators but NOT offset indicators
        has_length = any(ind in name_lower for ind in length_indicators)
        has_offset = any(ind in name_lower for ind in offset_indicators)
        
        return has_length and not has_offset


# =============================================================================
# MUTATOR - Packet-level mutation engine
# =============================================================================

class MutationType:
    """Types of packet mutations."""
    BIT_FLIP = 'bit_flip'
    BYTE_REPLACE = 'byte_replace'
    BYTE_INSERT = 'byte_insert'
    BYTE_DELETE = 'byte_delete'
    CHUNK_REPLACE = 'chunk_replace'
    TRUNCATE = 'truncate'
    EXTEND = 'extend'
    BYTEFLIP = 'byteflip'
    
    ALL = [BIT_FLIP, BYTE_REPLACE, BYTE_INSERT, BYTE_DELETE, 
           CHUNK_REPLACE, TRUNCATE, EXTEND]


class Mutator:
    """
    Packet-level mutation engine for blind fuzzing.
    
    Applies random mutations to raw packet data without knowledge
    of the protocol structure. Useful for finding parsing bugs.
    
    Usage:
        mutator = Mutator()
        mutated, info = mutator.mutate(packet_bytes)
        mutated, info = mutator.mutate(packet_bytes, mutation_type=MutationType.BIT_FLIP)
        mutated, info = mutator.byteflip(packet_bytes, count=3)
    """
    
    def __init__(self, skip_header=4):
        """
        Initialize mutator.
        
        Args:
            skip_header: Bytes to skip at start (e.g., 4 for NetBIOS header)
        """
        self.skip_header = skip_header
        self.fuzzer = Fuzzer()
        self.last_mutation = None
    
    def mutate(self, data, mutation_type=None):
        """
        Apply a random mutation to packet data.
        
        Args:
            data: Raw packet bytes
            mutation_type: Specific mutation or None for random
            
        Returns:
            tuple: (mutated_bytes, mutation_info_dict)
        """
        if len(data) < self.skip_header + 6:
            return data, {'type': 'none', 'details': ['packet too small']}
        
        packet = bytearray(data)
        original_len = len(packet)
        
        # Select mutation type
        if mutation_type is None:
            mutation_type = choice(MutationType.ALL)
        
        info = {'type': mutation_type, 'details': [], 'original_len': original_len}
        
        if mutation_type == MutationType.BIT_FLIP:
            packet, details = self._bit_flip(packet)
        elif mutation_type == MutationType.BYTE_REPLACE:
            packet, details = self._byte_replace(packet)
        elif mutation_type == MutationType.BYTE_INSERT:
            packet, details = self._byte_insert(packet)
        elif mutation_type == MutationType.BYTE_DELETE:
            packet, details = self._byte_delete(packet)
        elif mutation_type == MutationType.CHUNK_REPLACE:
            packet, details = self._chunk_replace(packet)
        elif mutation_type == MutationType.TRUNCATE:
            packet, details = self._truncate(packet)
        elif mutation_type == MutationType.EXTEND:
            packet, details = self._extend(packet)
        else:
            details = ['unknown mutation type']
        
        info['details'] = details
        info['final_len'] = len(packet)
        info['delta'] = len(packet) - original_len
        
        self.last_mutation = info
        return bytes(packet), info
    
    def byteflip(self, data, count=1):
        """
        Replace N random bytes with random values.
        
        Args:
            data: Raw packet bytes
            count: Number of bytes to flip
            
        Returns:
            tuple: (mutated_bytes, mutation_info_dict)
        """
        if len(data) < self.skip_header + 1:
            return data, {'type': 'byteflip', 'details': ['packet too small']}
        
        packet = bytearray(data)
        packet_len = len(packet)
        num_flips = min(count, packet_len - self.skip_header)
        
        flipped_offsets = set()
        details = []
        
        for _ in range(num_flips):
            # Find unique offset
            attempts = 0
            while attempts < 100:
                offset = randint(self.skip_header, packet_len - 1)
                if offset not in flipped_offsets:
                    flipped_offsets.add(offset)
                    break
                attempts += 1
            else:
                continue
            
            # Flip to different value
            original_byte = packet[offset]
            new_byte = randint(0, 255)
            while new_byte == original_byte and packet_len > 1:
                new_byte = randint(0, 255)
            
            packet[offset] = new_byte
            details.append({
                'offset': offset,
                'original': f'0x{original_byte:02x}',
                'new': f'0x{new_byte:02x}'
            })
        
        info = {
            'type': 'byteflip',
            'count': num_flips,
            'details': details
        }
        self.last_mutation = info
        return bytes(packet), info
    
    def _bit_flip(self, packet):
        """Flip random bits in random bytes."""
        details = []
        num_flips = randint(1, min(10, len(packet) - self.skip_header))
        
        for _ in range(num_flips):
            offset = randint(self.skip_header, len(packet) - 1)
            bit_pos = randint(0, 7)
            original = packet[offset]
            packet[offset] ^= (1 << bit_pos)
            details.append(f"offset {offset}, bit {bit_pos} (0x{original:02x} → 0x{packet[offset]:02x})")
        
        return packet, details
    
    def _byte_replace(self, packet):
        """Replace random bytes with fuzzed values."""
        details = []
        
        # Choose fuzz size: 1, 2, 4, or 8 bytes
        fuzz_size = choice([1, 2, 4, 8])
        fuzz_bytes, _ = self.fuzzer.fuzz(FieldType.INT, 0, fuzz_size)
        num_bytes = min(len(fuzz_bytes), len(packet) - self.skip_header)
        
        if num_bytes > 0:
            offset = randint(self.skip_header, len(packet) - num_bytes)
            packet[offset:offset + num_bytes] = fuzz_bytes[:num_bytes]
            details.append(f"offset {offset}, {num_bytes} bytes → {fuzz_bytes[:num_bytes].hex()}")
        
        return packet, details
    
    def _byte_insert(self, packet):
        """Insert fuzzed bytes at random position."""
        details = []
        
        insert_bytes, _ = self.fuzzer.fuzz(FieldType.STRING, b"")
        insert_len = min(len(insert_bytes), 100)
        insert_bytes = insert_bytes[:insert_len]
        
        offset = randint(self.skip_header, len(packet))
        packet[offset:offset] = insert_bytes
        
        display = insert_bytes[:32].hex() + ('...' if len(insert_bytes) > 32 else '')
        details.append(f"offset {offset}, inserted {len(insert_bytes)} bytes: {display}")
        
        return packet, details
    
    def _byte_delete(self, packet):
        """Delete random bytes."""
        details = []
        
        if len(packet) > self.skip_header + 10:
            num_delete = randint(1, min(20, len(packet) - self.skip_header - 10))
            offset = randint(self.skip_header, len(packet) - num_delete)
            deleted = bytes(packet[offset:offset + num_delete])
            del packet[offset:offset + num_delete]
            details.append(f"offset {offset}, deleted {num_delete} bytes: {deleted.hex()}")
        
        return packet, details
    
    def _chunk_replace(self, packet):
        """Replace a chunk with fuzzed string."""
        details = []
        
        chunk_bytes, _ = self.fuzzer.fuzz(FieldType.STRING, b"")
        chunk_size = min(len(chunk_bytes), len(packet) - self.skip_header - 10)
        
        if chunk_size > 0:
            offset = randint(self.skip_header, len(packet) - chunk_size)
            packet[offset:offset + chunk_size] = chunk_bytes[:chunk_size]
            display = chunk_bytes[:32].hex() + ('...' if len(chunk_bytes) > 32 else '')
            details.append(f"offset {offset}, {chunk_size} bytes → {display}")
        
        return packet, details
    
    def _truncate(self, packet):
        """Remove bytes from the end."""
        details = []
        
        if len(packet) > self.skip_header + 10:
            num_truncate = randint(1, min(50, len(packet) - self.skip_header - 10))
            truncated = bytes(packet[-num_truncate:])
            packet = packet[:-num_truncate]
            display = truncated[:32].hex() + ('...' if len(truncated) > 32 else '')
            details.append(f"truncated {num_truncate} bytes: {display}")
        
        return packet, details
    
    def _extend(self, packet):
        """Add bytes to the end."""
        details = []
        
        extend_bytes, _ = self.fuzzer.fuzz(FieldType.STRING, b"")
        extend_len = min(len(extend_bytes), 100)
        extend_bytes = extend_bytes[:extend_len]
        packet.extend(extend_bytes)
        
        display = extend_bytes[:32].hex() + ('...' if len(extend_bytes) > 32 else '')
        details.append(f"extended by {len(extend_bytes)} bytes: {display}")
        
        return packet, details
    
    def format_info(self, info):
        """Format mutation info for display."""
        lines = [f"Mutation: {info['type']}"]
        
        if 'original_len' in info:
            lines.append(f"  Size: {info['original_len']} → {info['final_len']} ({info['delta']:+d})")
        
        for detail in info.get('details', []):
            if isinstance(detail, dict):
                lines.append(f"  {detail['offset']}: {detail['original']} → {detail['new']}")
            else:
                lines.append(f"  {detail}")
        
        return '\n'.join(lines)


# =============================================================================
# PACKET PRINTER - Unified output formatting for all fuzzers
# =============================================================================

class PacketPrinter:
    """
    Unified packet output formatting for all fuzzers.
    
    Provides consistent hex dumps, field annotations, and mutation details
    across all protocol fuzzers using the OffByWon framework.
    
    Output format:
        ======================================================================
        SENDING PACKET #N (Length: X bytes) - packet_type
        Fuzzing: MODE (details)
          → mutation/field details
        ======================================================================
        hex_dump
        ======================================================================
    
    Usage:
        printer = PacketPrinter()
        
        # Field-level fuzzing
        printer.print_fuzzed_packet(packet, 'CREATE', 
            fuzzed_fields={'Length': b'\\xff\\xff'}, 
            fuzz_info='Length: max')
        
        # Blind mutation
        printer.print_fuzzed_packet(packet, 'NEGOTIATE', 
            mutation_info={'type': 'bit_flip', 'details': ['offset 10, bit 3']})
        
        # Byteflip
        printer.print_fuzzed_packet(packet, 'QUERY_INFO',
            byteflip_info={'count': 2, 'details': [{'offset': 10, 'original': '0x00', 'new': '0xff'}]})
    """
    
    def __init__(self, width=70):
        """
        Initialize printer.
        
        Args:
            width: Width of separator lines
        """
        self.width = width
        self.packet_count = 0
    
    def print_fuzzed_packet(self, packet, packet_type=None, fuzzed_fields=None, 
                            fuzz_info=None, mutation_info=None, byteflip_info=None,
                            combined_info=None):
        """
        Print packet with unified fuzzing output format.
        
        Args:
            packet: Raw packet bytes
            packet_type: Type of packet (e.g., 'NEGOTIATE', 'CREATE')
            fuzzed_fields: dict of field_name -> fuzz_bytes (field-level fuzzing)
            fuzz_info: String description of fuzzing strategy
            mutation_info: dict from Mutator.mutate() (blind fuzzing)
            byteflip_info: dict from Mutator.byteflip()
            combined_info: dict with bit flip info from combined mode
        """
        self.packet_count += 1
        
        print("=" * self.width)
        print(f"SENDING PACKET #{self.packet_count} (Length: {len(packet)} bytes) - {packet_type or 'unknown'}")
        
        # Determine what kind of fuzzing was applied
        if mutation_info:
            print(f"Fuzzing: BLIND mutation ({mutation_info.get('type', 'unknown')})")
            for detail in mutation_info.get('details', []):
                print(f"  → {detail}")
            if 'delta' in mutation_info:
                print(f"  Size: {mutation_info.get('original_len', '?')} → {mutation_info.get('final_len', '?')} ({mutation_info['delta']:+d})")
        
        elif byteflip_info:
            print(f"Fuzzing: BYTEFLIP ({byteflip_info.get('count', 0)} byte(s))")
            for detail in byteflip_info.get('details', []):
                if isinstance(detail, dict):
                    print(f"  → offset {detail['offset']}: {detail['original']} → {detail['new']}")
                else:
                    print(f"  → {detail}")
        
        elif fuzzed_fields:
            print(f"Fuzzing: FIELD ({len(fuzzed_fields)} field(s))")
            for field_name, fuzz_bytes in fuzzed_fields.items():
                if isinstance(fuzz_bytes, bytes):
                    hex_val = fuzz_bytes.hex()
                    if len(hex_val) <= 16:
                        print(f"  → {field_name} = 0x{hex_val} ({len(fuzz_bytes)} bytes)")
                    else:
                        print(f"  → {field_name} = {hex_val[:32]}... ({len(fuzz_bytes)} bytes)")
                else:
                    print(f"  → {field_name} = {fuzz_bytes}")
            if fuzz_info:
                print(f"  Strategy: {fuzz_info}")
        
        else:
            print("Fuzzing: None (clean packet)")
        
        # Show combined mode bit flip
        if combined_info:
            print(f"Combined: bit flip at offset {combined_info['offset']}, bit {combined_info['bit']} (0x{combined_info['original']:02x} → 0x{combined_info['flipped']:02x})")
        
        print("=" * self.width)
        print(packet.hex())
        print("=" * self.width)
    
    # Legacy methods for backward compatibility
    def print_packet(self, packet, packet_type=None, fuzzed_fields=None, fuzz_info=None):
        """Legacy method - use print_fuzzed_packet instead."""
        self.print_fuzzed_packet(packet, packet_type, fuzzed_fields=fuzzed_fields, fuzz_info=fuzz_info)
    
    def print_mutation(self, info):
        """Print mutation details standalone (without packet)."""
        print(f"[MUTATION] Type: {info.get('type', 'unknown')}")
        if 'original_len' in info:
            print(f"[MUTATION] Size: {info['original_len']} → {info['final_len']} ({info['delta']:+d})")
        for detail in info.get('details', []):
            if isinstance(detail, dict):
                print(f"[MUTATION]   offset {detail['offset']}: {detail['original']} → {detail['new']}")
            else:
                print(f"[MUTATION]   {detail}")
    
    def print_byteflip(self, info):
        """Print byteflip details standalone (without packet)."""
        count = info.get('count', 0)
        print(f"[BYTEFLIP] Flipped {count} byte(s)")
        for detail in info.get('details', []):
            if isinstance(detail, dict):
                print(f"[BYTEFLIP]   offset {detail['offset']}: {detail['original']} → {detail['new']}")
            else:
                print(f"[BYTEFLIP]   {detail}")
    
    def print_hex_annotated(self, data, annotations=None, bytes_per_line=16):
        """
        Print annotated hex dump with offsets and optional field markers.
        
        Args:
            data: Raw packet bytes
            annotations: dict of offset -> field_name (optional)
            bytes_per_line: Bytes per line (default 16)
        """
        annotations = annotations or {}
        
        for i in range(0, len(data), bytes_per_line):
            chunk = data[i:i + bytes_per_line]
            hex_part = chunk.hex()
            
            # Add spacing every 2 bytes for readability
            spaced_hex = ' '.join(hex_part[j:j+4] for j in range(0, len(hex_part), 4))
            
            # Check for annotations in this range
            field_markers = []
            for offset, field_name in annotations.items():
                if i <= offset < i + bytes_per_line:
                    field_markers.append(f"[{offset}: {field_name}]")
            
            marker_str = ' '.join(field_markers) if field_markers else ''
            
            print(f"{i:04x}: {spaced_hex:<{bytes_per_line * 2 + bytes_per_line // 2}}  {marker_str}")


# =============================================================================
# OVERFLOW GENERATOR - Count/size overflow attacks
# =============================================================================

class OverflowGenerator:
    """
    Generate data for count/size overflow attacks.
    
    Creates arrays with mismatched counts/sizes to trigger
    buffer overflows in array parsing code.
    
    Usage:
        gen = OverflowGenerator()
        items = gen.generate_items(count=1000, item_size=2, value='sequential')
        data = gen.build_overflow_array(count=100, actual_count=1000, item_size=2)
    """
    
    # Common item values for different attack scenarios
    VALUES = {
        'encryption': 0x0001,   # AES-128-CCM cipher ID
        'signing': 0x0002,      # AES-128-CMAC signing ID
        'compression': 0x0001,  # LZNT1 compression ID
        'zero': 0x0000,
        'max_16': 0xFFFF,
        'max_32': 0xFFFFFFFF,
    }
    
    def generate_items(self, count, item_size=2, value='sequential'):
        """
        Generate array items for overflow testing.
        
        Args:
            count: Number of items to generate
            item_size: Size of each item in bytes (1, 2, 4, 8)
            value: Item value strategy:
                - 'sequential': 0, 1, 2, 3, ...
                - 'random': random values
                - 'encryption', 'signing', etc.: constant from VALUES
                - int: use this constant value
                
        Returns:
            bytes: Packed items
        """
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(item_size, '<H')
        max_val = (1 << (item_size * 8)) - 1
        
        items = bytearray()
        for i in range(count):
            if value == 'sequential':
                val = i & max_val
            elif value == 'random':
                val = randint(0, max_val)
            elif isinstance(value, int):
                val = value & max_val
            elif value in self.VALUES:
                val = self.VALUES[value] & max_val
            else:
                val = 0
            
            items.extend(struct.pack(fmt, val))
        
        return bytes(items)
    
    def build_overflow_array(self, declared_count, actual_count, item_size=2, value='sequential'):
        """
        Build an array with mismatched declared vs actual count.
        
        Args:
            declared_count: Count field value (what header says)
            actual_count: Actual number of items in data
            item_size: Size of each item in bytes
            value: Item value strategy
            
        Returns:
            tuple: (count_for_header, item_bytes)
        """
        items = self.generate_items(actual_count, item_size, value)
        return declared_count, items
    
    def build_length_mismatch(self, declared_length, actual_data):
        """
        Return data with mismatched length field.
        
        Args:
            declared_length: Length to put in header
            actual_data: Actual data bytes
            
        Returns:
            tuple: (declared_length, actual_data)
        """
        return declared_length, actual_data


# =============================================================================
# PACKET FIELD - Represents a single field in a packet
# =============================================================================

class PacketField:
    """
    Represents a field in a packet with its type and fuzzing behavior.
    
    Usage:
        field = PacketField("Length", FieldType.LENGTH, size=4, default=0)
        field = PacketField("Filename", FieldType.STRING, default=b"test.txt")
    """
    
    def __init__(self, name, field_type, size=None, default=None, pack_fmt=None):
        """
        Define a packet field.
        
        Args:
            name: Field name for display
            field_type: FieldType constant
            size: Size in bytes (auto-detected for some types)
            default: Default value
            pack_fmt: Optional struct format (e.g., '<I', '<H')
        """
        self.name = name
        self.type = field_type
        self.size = size
        self.default = default
        self.pack_fmt = pack_fmt
        
        # Auto-detect size from pack_fmt
        if pack_fmt and not size:
            self.size = struct.calcsize(pack_fmt)
    
    def pack(self, value=None):
        """Pack value to bytes."""
        val = value if value is not None else self.default
        
        if self.pack_fmt:
            return struct.pack(self.pack_fmt, val)
        elif isinstance(val, bytes):
            return val
        elif isinstance(val, int):
            fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(self.size, '<I')
            return struct.pack(fmt, val)
        else:
            return bytes(val) if val else b""


# =============================================================================
# PACKET BUILDER - Build and fuzz packets easily
# =============================================================================

class PacketBuilder:
    """
    Build packets with automatic fuzzing support.
    
    Usage:
        builder = PacketBuilder("SMB2_READ")
        builder.add_field("StructureSize", FieldType.INT, size=2, default=49)
        builder.add_field("Length", FieldType.LENGTH, size=4, default=4096)
        builder.add_field("Filename", FieldType.STRING, default=b"test.txt")
        
        # Build clean packet
        packet = builder.build()
        
        # Build with fuzzing
        packet, fuzz_info = builder.build_fuzzed(fuzz_types=[FieldType.LENGTH])
    """
    
    def __init__(self, name="Packet"):
        self.name = name
        self.fields = []
        self.fuzzer = Fuzzer()
    
    def add_field(self, name, field_type, size=None, default=None, pack_fmt=None):
        """Add a field to the packet."""
        self.fields.append(PacketField(name, field_type, size, default, pack_fmt))
        return self  # Allow chaining
    
    def add_int(self, name, size, default=0):
        """Shorthand for adding an integer field."""
        return self.add_field(name, FieldType.INT, size=size, default=default)
    
    def add_length(self, name, size, default=0):
        """Shorthand for adding a length field."""
        return self.add_field(name, FieldType.LENGTH, size=size, default=default)
    
    def add_string(self, name, default=b""):
        """Shorthand for adding a string field."""
        return self.add_field(name, FieldType.STRING, default=default)
    
    def add_bytes(self, name, size=None, default=b""):
        """Shorthand for adding a bytes field."""
        return self.add_field(name, FieldType.BYTES, size=size, default=default)
    
    def set_mode(self, mode):
        """Set fuzzing mode (standard/extended/boundary/power2)."""
        self.fuzzer = Fuzzer(mode=mode)
        return self
    
    def build(self, values=None):
        """
        Build packet with default or provided values.
        
        Args:
            values: Optional dict of field_name -> value overrides
            
        Returns:
            bytes: Packed packet
        """
        values = values or {}
        parts = []
        
        for field in self.fields:
            val = values.get(field.name, field.default)
            parts.append(field.pack(val))
        
        return b"".join(parts)
    
    def build_fuzzed(self, fuzz_fields=None, fuzz_types=None, num_fields=1, values=None):
        """
        Build packet with fuzzing applied.
        
        Args:
            fuzz_fields: List of field names to fuzz (None = auto-select)
            fuzz_types: List of FieldTypes to target (e.g., [FieldType.LENGTH])
            num_fields: Number of fields to fuzz if auto-selecting
            values: Optional dict of field_name -> value overrides
            
        Returns:
            Tuple of (packet_bytes, fuzz_info_list)
            fuzz_info_list: [(field_name, original, fuzzed_bytes, description), ...]
        """
        values = values or {}
        parts = []
        fuzz_info = []
        
        # Determine which fields to fuzz
        if fuzz_fields:
            fields_to_fuzz = set(fuzz_fields)
        elif fuzz_types:
            # Select fields matching the specified types
            matching = [f.name for f in self.fields if f.type in fuzz_types]
            fields_to_fuzz = set(matching)
        else:
            # Auto-select random fields
            candidates = [f.name for f in self.fields]
            fields_to_fuzz = set(sample(candidates, min(num_fields, len(candidates))))
        
        for field in self.fields:
            original = values.get(field.name, field.default)
            
            if field.name in fields_to_fuzz:
                # Fuzz this field
                fuzzed_bytes, desc = self.fuzzer.fuzz(field.type, original, field.size)
                parts.append(fuzzed_bytes)
                
                # Record fuzz info
                if isinstance(original, int):
                    orig_str = f"0x{original:x}"
                elif isinstance(original, bytes):
                    orig_str = original.hex()[:16] + "..." if len(original) > 8 else original.hex()
                else:
                    orig_str = str(original)
                
                fuzzed_str = fuzzed_bytes.hex()[:16] + "..." if len(fuzzed_bytes) > 8 else fuzzed_bytes.hex()
                fuzz_info.append((field.name, orig_str, fuzzed_str, desc))
            else:
                # Use original value
                parts.append(field.pack(original))
        
        return b"".join(parts), fuzz_info
    
    def print_fuzz_result(self, packet, fuzz_info, packet_num=None):
        """
        Print fuzzing result in standard format.
        
        Args:
            packet: The fuzzed packet bytes
            fuzz_info: List from build_fuzzed()
            packet_num: Optional packet number
        """
        print("=" * 70)
        header = f"PACKET #{packet_num}" if packet_num else "FUZZED PACKET"
        print(f"{header} ({self.name}, {len(packet)} bytes)")
        
        if fuzz_info:
            print(f"Fuzzed fields: {[f[0] for f in fuzz_info]}")
            for name, orig, fuzzed, desc in fuzz_info:
                print(f"  {name}: {orig} -> {fuzzed} ({desc})")
        else:
            print("Fuzzed fields: None (clean packet)")
        
        print("=" * 70)
        print(packet.hex())
        print("=" * 70)


# =============================================================================
# LENGTH DELTA GENERATOR - Count/length mismatch testing
# =============================================================================

class LengthDeltaGenerator:
    """
    Generate length/count field deltas for off-by-one testing.
    
    The classic vulnerability pattern: Count says N items, but DataLength 
    says space for N+1 or N-1. This class provides systematic testing of
    these mismatches.

    """
    
    # Standard deltas for off-by-one testing
    STANDARD_DELTAS = [-4, -3, -2, -1, +1, +2, +3, +4]
    
    # Extended deltas for deeper testing
    EXTENDED_DELTAS = [-8, -7, -6, -5, -4, -3, -2, -1, +1, +2, +3, +4, +5, +6, +7, +8]
    
    # Boundary-focused deltas
    BOUNDARY_DELTAS = [-1, +1]
    
    # Power-of-two deltas (alignment boundaries)
    POWER_OF_TWO_DELTAS = [-16, -8, -4, -2, -1, +1, +2, +4, +8, +16]
    
    def __init__(self, mode='standard'):
        """
        Initialize delta generator.
        
        Args:
            mode: 'standard' (+/-1 to +/-4), 'extended' (+/-1 to +/-8),
                  'boundary' (+/-1 only), 'power2' (power-of-two deltas)
        """
        self.mode = mode
        if mode == 'standard':
            self.deltas = self.STANDARD_DELTAS
        elif mode == 'extended':
            self.deltas = self.EXTENDED_DELTAS
        elif mode == 'boundary':
            self.deltas = self.BOUNDARY_DELTAS
        elif mode == 'power2':
            self.deltas = self.POWER_OF_TWO_DELTAS
        else:
            self.deltas = self.STANDARD_DELTAS
    
    def get_deltas(self):
        """Get list of deltas to test."""
        return self.deltas.copy()
    
    def generate_test_cases(self, base_count, item_size=1):
        """
        Generate test cases for count/length mismatch testing.
        
        Args:
            base_count: The actual number of items
            item_size: Size of each item in bytes
        
        Returns:
            List of (test_type, count_delta, length_delta, description) tuples
        """
        test_cases = []
        
        # Phase 1: Correct count, wrong DataLength
        for delta in self.deltas:
            data_length_delta = delta * item_size  # Scale by item size
            test_cases.append((
                'data_length_mismatch',
                0,  # count_delta
                data_length_delta,
                f"Count={base_count}, DataLength{data_length_delta:+d}"
            ))
        
        # Phase 2: Wrong count, correct DataLength
        for delta in self.deltas:
            if base_count + delta >= 0:  # Ensure non-negative count
                test_cases.append((
                    'count_mismatch',
                    delta,  # count_delta
                    0,  # length_delta
                    f"Count={base_count + delta} (base{delta:+d}), DataLength=correct"
                ))
        
        return test_cases
    
    def generate_combined_test_cases(self, base_count, item_size=1):
        """
        Generate combined mismatch test cases (both count AND length wrong).
        
        This tests scenarios where both fields are off, potentially 
        causing different behavior than single-field mismatches.
        """
        test_cases = []
        
        for count_delta in [-1, +1]:
            for length_delta in [-1, +1]:
                if base_count + count_delta >= 0:
                    data_length_delta = length_delta * item_size
                    test_cases.append((
                        'combined_mismatch',
                        count_delta,
                        data_length_delta,
                        f"Count={base_count + count_delta} ({count_delta:+d}), DataLength{data_length_delta:+d}"
                    ))
        
        return test_cases
    
    @staticmethod
    def apply_delta(value, delta, min_val=0, max_val=0xFFFFFFFF):
        """
        Apply delta to a value with bounds checking.
        
        Args:
            value: Original value
            delta: Delta to apply
            min_val: Minimum allowed value
            max_val: Maximum allowed value
        
        Returns:
            Bounded result
        """
        result = value + delta
        if result < min_val:
            result = min_val
        if result > max_val:
            result = max_val
        return result


class DERScanner:
    """
    scanner for identifying DER/BER/ASN.1 encoding positions in binary data.
    
    Supports:
    - All universal ASN.1 tags (primitive and constructed)
    - Application and context-specific tags
    - Long-form tag encoding
    - Definite and indefinite length encoding
    - Nested structure parsing with depth tracking
    - OID decoding
    - Structure validation to reduce false positives
    
    """
    
    # Universal class tags (0x00-0x1F)
    UNIVERSAL_TAGS = {
        0x01: 'BOOLEAN',
        0x02: 'INTEGER',
        0x03: 'BIT_STRING',
        0x04: 'OCTET_STRING',
        0x05: 'NULL',
        0x06: 'OID',
        0x07: 'ObjectDescriptor',
        0x08: 'EXTERNAL',
        0x09: 'REAL',
        0x0a: 'ENUMERATED',
        0x0b: 'EMBEDDED_PDV',
        0x0c: 'UTF8String',
        0x0d: 'RELATIVE_OID',
        0x0e: 'TIME',
        0x10: 'SEQUENCE',      # Always constructed (0x30)
        0x11: 'SET',           # Always constructed (0x31)
        0x12: 'NumericString',
        0x13: 'PrintableString',
        0x14: 'T61String',
        0x15: 'VideotexString',
        0x16: 'IA5String',
        0x17: 'UTCTime',
        0x18: 'GeneralizedTime',
        0x19: 'GraphicString',
        0x1a: 'VisibleString',
        0x1b: 'GeneralString',
        0x1c: 'UniversalString',
        0x1d: 'CHARACTER_STRING',
        0x1e: 'BMPString',
        0x1f: 'LONG_FORM',     # Long form tag indicator
    }
    
    # Tag class masks
    CLASS_UNIVERSAL = 0x00
    CLASS_APPLICATION = 0x40
    CLASS_CONTEXT = 0x80
    CLASS_PRIVATE = 0xc0
    
    # Constructed bit
    CONSTRUCTED = 0x20
    
    # Common OID prefixes
    KNOWN_OIDS = {
        '1.2.840.113549.1.1': 'PKCS#1 (RSA)',
        '1.2.840.113549.1.7': 'PKCS#7',
        '1.2.840.113549.1.9': 'PKCS#9',
        '1.2.840.10040.4': 'DSA',
        '1.2.840.10045.2': 'EC Public Key',
        '1.2.840.10045.3': 'EC Named Curves',
        '1.2.840.10045.4': 'ECDSA',
        '1.3.6.1.4.1.311': 'Microsoft',
        '1.3.6.1.5.5.7': 'PKIX',
        '1.3.14.3.2': 'OIW secsig',
        '2.5.4': 'X.500 AttributeType',
        '2.5.29': 'X.509 Extensions',
        '2.16.840.1.101.3.4': 'NIST Algorithms',
        '1.3.6.1.5.5.2': 'SPNEGO',
        '1.2.840.48018.1.2.2': 'MS Kerberos',
        '1.2.840.113554.1.2.2': 'Kerberos 5',
    }
    
    def __init__(self, strict=False, max_depth=32):
        """
        Initialize scanner.
        
        Args:
            strict: If True, only report high-confidence ASN.1 structures
            max_depth: Maximum nesting depth to parse
        """
        self.strict = strict
        self.max_depth = max_depth
        self.structures = []  # Parsed ASN.1 structures
    
    @classmethod
    def get_tag_class_name(cls, tag_byte):
        """Get the class name for a tag byte."""
        tag_class = tag_byte & 0xc0
        if tag_class == cls.CLASS_UNIVERSAL:
            return 'UNIVERSAL'
        elif tag_class == cls.CLASS_APPLICATION:
            return 'APPLICATION'
        elif tag_class == cls.CLASS_CONTEXT:
            return 'CONTEXT'
        else:
            return 'PRIVATE'
    
    @classmethod
    def is_constructed(cls, tag_byte):
        """Check if tag indicates constructed encoding."""
        return bool(tag_byte & cls.CONSTRUCTED)
    
    @classmethod
    def get_tag_number(cls, tag_byte):
        """Get the tag number from first byte."""
        return tag_byte & 0x1f
    
    @classmethod
    def parse_long_tag(cls, data, offset):
        """
        Parse long-form tag (tag number >= 31).
        Returns (tag_number, bytes_consumed) or (None, 0) on error.
        """
        if offset >= len(data):
            return None, 0
        
        first_byte = data[offset]
        if (first_byte & 0x1f) != 0x1f:
            # Not a long-form tag
            return first_byte & 0x1f, 1
        
        # Long form: subsequent bytes encode tag number
        tag_number = 0
        bytes_consumed = 1
        
        while offset + bytes_consumed < len(data):
            b = data[offset + bytes_consumed]
            bytes_consumed += 1
            tag_number = (tag_number << 7) | (b & 0x7f)
            
            if not (b & 0x80):  # Last byte
                break
            
            if bytes_consumed > 5:  # Sanity limit
                return None, 0
        
        return tag_number, bytes_consumed
    
    @classmethod
    def parse_length(cls, data, offset):
        """
        Parse DER/BER length field.
        Returns (length, bytes_consumed) or (None, bytes_consumed) for indefinite.
        """
        if offset >= len(data):
            return None, 0
        
        first_byte = data[offset]
        
        # Short form: length < 128
        if first_byte < 0x80:
            return first_byte, 1
        
        # Indefinite length (BER only, not valid DER)
        if first_byte == 0x80:
            return None, 1  # None indicates indefinite
        
        # Long form: first byte indicates number of length bytes
        num_length_bytes = first_byte & 0x7f
        
        if num_length_bytes > 6:  # Sanity limit (48-bit length)
            return None, 0
        
        if offset + 1 + num_length_bytes > len(data):
            return None, 0
        
        length_val = 0
        for i in range(num_length_bytes):
            length_val = (length_val << 8) | data[offset + 1 + i]
        
        return length_val, 1 + num_length_bytes
    
    @classmethod
    def decode_oid(cls, data):
        """Decode an OID from raw bytes."""
        if not data or len(data) < 1:
            return None
        
        components = []
        
        # First byte encodes first two components
        first = data[0]
        components.append(first // 40)
        components.append(first % 40)
        
        # Remaining bytes encode subsequent components
        value = 0
        for byte in data[1:]:
            value = (value << 7) | (byte & 0x7f)
            if not (byte & 0x80):
                components.append(value)
                value = 0
        
        return '.'.join(str(c) for c in components)
    
    @classmethod
    def get_tag_name(cls, tag_byte, tag_number=None):
        """Get human-readable tag name."""
        tag_class = tag_byte & 0xc0
        is_constructed = bool(tag_byte & cls.CONSTRUCTED)
        
        if tag_number is None:
            tag_number = tag_byte & 0x1f
        
        suffix = '/C' if is_constructed else ''
        
        if tag_class == cls.CLASS_UNIVERSAL:
            if tag_byte in (0x30, 0x31):  # SEQUENCE/SET are always constructed
                name = cls.UNIVERSAL_TAGS.get(tag_byte & 0x1f, f'UNKNOWN_{tag_number}')
            else:
                name = cls.UNIVERSAL_TAGS.get(tag_number, f'UNKNOWN_{tag_number}')
            return f'{name}{suffix}'
        elif tag_class == cls.CLASS_APPLICATION:
            return f'APPLICATION_{tag_number}{suffix}'
        elif tag_class == cls.CLASS_CONTEXT:
            return f'[{tag_number}]{suffix}'
        else:
            return f'PRIVATE_{tag_number}{suffix}'
    
    def is_valid_structure(self, data, offset):
        """
        Check if offset points to a valid ASN.1 structure.
        Returns (is_valid, tag_bytes, length, length_bytes) or (False, 0, 0, 0).
        """
        if offset >= len(data):
            return False, 0, 0, 0
        
        tag_byte = data[offset]
        
        # Parse tag (handle long form)
        tag_number, tag_bytes = self.parse_long_tag(data, offset)
        if tag_number is None:
            return False, 0, 0, 0
        
        # Parse length
        length_offset = offset + tag_bytes
        length, length_bytes = self.parse_length(data, length_offset)
        
        if length_bytes == 0:
            return False, 0, 0, 0
        
        # For definite length, check if value fits in remaining data
        if length is not None:
            total_size = tag_bytes + length_bytes + length
            if offset + total_size > len(data):
                return False, 0, 0, 0
        
        # Additional validation for strict mode
        if self.strict:
            tag_class = tag_byte & 0xc0
            
            # Universal class: check for known tags
            if tag_class == self.CLASS_UNIVERSAL:
                base_tag = tag_byte & 0x1f
                if base_tag not in self.UNIVERSAL_TAGS and base_tag != 0x1f:
                    return False, 0, 0, 0
            
            # NULL must have length 0
            if tag_byte == 0x05 and length != 0:
                return False, 0, 0, 0
            
            # BOOLEAN must have length 1
            if tag_byte == 0x01 and length != 1:
                return False, 0, 0, 0
        
        return True, tag_bytes, length, length_bytes
    
    def scan(self, data, start_offset=0):
        """
        Scan data for ASN.1/DER structures, recursing into nested content.
        
        Args:
            data: Bytes to scan
            start_offset: Offset to start scanning from
        
        Returns:
            List of (offset, type, description) tuples
        """
        if isinstance(data, bytes):
            data = bytearray(data)
        
        positions = []
        self._scan_recursive_impl(data, start_offset, positions, depth=0)
        return positions
    
    def _scan_recursive_impl(self, data, offset, positions, depth):
        """Internal recursive scanner that finds ALL tag/length positions."""
        if depth > self.max_depth:
            return offset
        
        while offset < len(data):
            is_valid, tag_bytes, length, length_bytes = self.is_valid_structure(data, offset)
            
            if not is_valid:
                offset += 1
                continue
            
            tag_byte = data[offset]
            tag_number, _ = self.parse_long_tag(data, offset)
            tag_name = self.get_tag_name(tag_byte, tag_number)
            
            # Record tag position
            if tag_bytes == 1:
                positions.append((offset, 'TAG', f'{tag_name} (0x{tag_byte:02x})'))
            else:
                positions.append((offset, 'TAG_LONG', f'{tag_name} ({tag_bytes} bytes)'))
                for i in range(1, tag_bytes):
                    positions.append((offset + i, 'TAG_BYTE', f'tag byte {i}'))
            
            # Record length position(s)
            length_offset = offset + tag_bytes
            if length_bytes == 1:
                len_byte = data[length_offset]
                if length is not None:
                    positions.append((length_offset, 'LENGTH', f'len={length} (0x{len_byte:02x})'))
                else:
                    positions.append((length_offset, 'LENGTH_INDEF', 'indefinite length'))
            else:
                indicator = data[length_offset]
                num_len_bytes = indicator & 0x7f
                positions.append((length_offset, 'LENGTH_LONG', f'{num_len_bytes}-byte length (0x{indicator:02x})'))
                for i in range(1, length_bytes):
                    positions.append((length_offset + i, 'LENGTH_BYTE', f'length byte {i} (0x{data[length_offset + i]:02x})'))
            
            # For OID, decode and show value
            if tag_byte == 0x06 and length is not None and length > 0:
                value_offset = offset + tag_bytes + length_bytes
                oid_data = data[value_offset:value_offset + length]
                oid_str = self.decode_oid(oid_data)
                if oid_str:
                    oid_name = None
                    for prefix, name in self.KNOWN_OIDS.items():
                        if oid_str.startswith(prefix):
                            oid_name = name
                            break
                    if oid_name:
                        positions.append((value_offset, 'OID_VALUE', f'{oid_str} ({oid_name})'))
                    else:
                        positions.append((value_offset, 'OID_VALUE', oid_str))
            
            if length is None:
                # Indefinite length - skip tag and length indicator
                offset += tag_bytes + length_bytes
                continue
            
            value_offset = offset + tag_bytes + length_bytes
            value_end = value_offset + length
            
            # ALWAYS recurse into constructed types
            if self.is_constructed(tag_byte):
                self._scan_recursive_impl(data, value_offset, positions, depth + 1)
            # Also recurse into OCTET STRING - often contains nested ASN.1 (SPNEGO, NTLM wrappers)
            elif tag_byte == 0x04 and length >= 2:
                # Check if content looks like ASN.1
                if value_offset < len(data):
                    inner_byte = data[value_offset]
                    # Common ASN.1 tags that might be inside OCTET STRING
                    if inner_byte in (0x30, 0x31, 0x60, 0xa0, 0xa1, 0xa2, 0xa3, 0x04, 0x06):
                        self._scan_recursive_impl(data, value_offset, positions, depth + 1)
            
            offset = value_end
        
        return offset
    
    def scan_recursive(self, data, start_offset=0, depth=0):
        """
        Recursively scan nested ASN.1 structures.
        
        Returns list of (offset, depth, type, description) tuples.
        """
        if isinstance(data, bytes):
            data = bytearray(data)
        
        if depth > self.max_depth:
            return []
        
        positions = []
        offset = start_offset
        
        while offset < len(data):
            is_valid, tag_bytes, length, length_bytes = self.is_valid_structure(data, offset)
            
            if not is_valid:
                offset += 1
                continue
            
            tag_byte = data[offset]
            tag_number, _ = self.parse_long_tag(data, offset)
            tag_name = self.get_tag_name(tag_byte, tag_number)
            is_constructed = self.is_constructed(tag_byte)
            
            # Record this structure
            total_header = tag_bytes + length_bytes
            positions.append((offset, depth, 'STRUCTURE', f'{tag_name} len={length}'))
            
            # Record tag
            positions.append((offset, depth, 'TAG', f'{tag_name} (0x{tag_byte:02x})'))
            
            # Record length
            length_offset = offset + tag_bytes
            if length_bytes == 1:
                positions.append((length_offset, depth, 'LENGTH', f'len={length}'))
            else:
                positions.append((length_offset, depth, 'LENGTH_LONG', f'{length_bytes}-byte length'))
                for i in range(1, length_bytes):
                    positions.append((length_offset + i, depth, 'LENGTH_BYTE', f'byte {i}'))
            
            # Recurse into constructed types
            if is_constructed and length is not None and length > 0:
                value_offset = offset + total_header
                nested = self.scan_recursive(data[value_offset:value_offset + length], 0, depth + 1)
                # Adjust offsets for nested results
                for n_off, n_depth, n_type, n_desc in nested:
                    positions.append((value_offset + n_off, n_depth, n_type, n_desc))
            
            # Move to next structure
            if length is not None:
                offset += total_header + length
            else:
                offset += total_header
        
        return positions
    
    def get_fuzzable_positions(self, data):
        """
        Get deduplicated list of fuzzable positions.
        
        Returns list of (offset, description) tuples.
        """
        all_positions = self.scan(data)
        seen = {}
        for offset, byte_type, desc in all_positions:
            if offset not in seen:
                seen[offset] = f"{byte_type}: {desc}"
        return [(offset, desc) for offset, desc in sorted(seen.items())]
    
    @classmethod
    def scan_positions(cls, data, strict=False):
        """
        Class method to scan for fuzzable positions.
        
        Convenience wrapper for calling without instantiation:
            positions = DERScanner.scan_positions(data)
        """
        scanner = cls(strict=strict)
        return scanner.get_fuzzable_positions(data)
    
    def get_structure_summary(self, data):
        """
        Get a summary of ASN.1 structures found.
        
        Returns list of structure descriptions with offsets and sizes.
        """
        if isinstance(data, bytes):
            data = bytearray(data)
        
        structures = []
        offset = 0
        
        while offset < len(data):
            is_valid, tag_bytes, length, length_bytes = self.is_valid_structure(data, offset)
            
            if is_valid and length is not None:
                tag_byte = data[offset]
                tag_name = self.get_tag_name(tag_byte)
                total_size = tag_bytes + length_bytes + length
                
                structures.append({
                    'offset': offset,
                    'tag': tag_byte,
                    'tag_name': tag_name,
                    'header_size': tag_bytes + length_bytes,
                    'value_size': length,
                    'total_size': total_size,
                    'constructed': self.is_constructed(tag_byte),
                })
                
                offset += total_size
            else:
                offset += 1
        
        return structures


# =============================================================================
# ARRAY FUZZER - Specialized fuzzing for count/element arrays
# =============================================================================

class ArrayFuzzer:
    """
    Helper class for array overflow testing.
    
    Arrays in binary protocols often have this structure:
    - Count field (1-4 bytes): How many elements follow
    - Element data: The actual array elements
    
    Bugs occur when:
    - Count says more elements than actually present (OOB read)
    - Count says fewer elements than present (data ignored, logic bugs)
    - Count is huge but data is tiny (integer overflow, heap overflow)
    - Count is 0 but data is present (null pointer, logic bugs)
    
    Usage:
        # Define how to build one element (protocol-specific)
        def build_nego_context(ctx_type, ctx_data):
            header = struct.pack('<HHI', ctx_type, len(ctx_data), 0)
            return header + ctx_data
        
        # Create array fuzzer
        array_fuzz = ArrayFuzzer(
            count_size=2,  # Count field is 2 bytes (USHORT)
            element_builder=build_nego_context,
        )
        
        # Add normal elements
        array_fuzz.add_element(0x0001, b"preauth_data")
        array_fuzz.add_element(0x0002, b"encryption_caps")
        
        # Get fuzzed output: (count_bytes, array_data_bytes, description)
        count_bytes, data_bytes, desc = array_fuzz.fuzz()
        
        # Or iterate through all test cases
        for count_bytes, data_bytes, desc in array_fuzz.generate_test_cases():
            packet = header + count_bytes + data_bytes
            send(packet)
    """
    
    # Fuzzing strategies
    STRATEGY_COUNT_OVERFLOW = 'count_overflow'
    STRATEGY_COUNT_UNDERFLOW = 'count_underflow'
    STRATEGY_ZERO_COUNT = 'zero_count'
    STRATEGY_HUGE_COUNT = 'huge_count'
    STRATEGY_COUNT_DELTA = 'count_delta'
    STRATEGY_DUPLICATE = 'duplicate'
    STRATEGY_INTEGER_OVERFLOW = 'integer_overflow'
    
    def __init__(self, count_size=2, element_builder=None, count_signed=False):
        """
        Initialize the array fuzzer.
        
        Args:
            count_size: Size of count field in bytes (1, 2, or 4)
            element_builder: Function to build one element from args
            count_signed: Whether count field is signed (rare)
        """
        self.count_size = count_size
        self.element_builder = element_builder
        self.count_signed = count_signed
        self.elements = []
        self.element_args = []
        
        if count_signed:
            self.max_count = (1 << (count_size * 8 - 1)) - 1
        else:
            self.max_count = (1 << (count_size * 8)) - 1
        
        self.interesting_counts = self._generate_interesting_counts()
    
    def _generate_interesting_counts(self):
        counts = [0, 1, self.max_count, self.max_count - 1]
        if self.count_size >= 1:
            counts.extend([0x7f, 0x80, 0xff])
        if self.count_size >= 2:
            counts.extend([0x7fff, 0x8000, 0xffff])
        if self.count_size >= 4:
            counts.extend([0x7fffffff, 0x80000000, 0xffffffff])
        counts = [c for c in counts if 0 <= c <= self.max_count]
        return list(set(counts))
    
    def add_element(self, *args, **kwargs):
        """Add an element using element_builder or raw bytes."""
        if self.element_builder:
            self.element_args.append((args, kwargs))
            element_bytes = self.element_builder(*args, **kwargs)
        else:
            element_bytes = args[0] if args else b""
            self.element_args.append(((element_bytes,), {}))
        self.elements.append(element_bytes)
    
    def add_raw_element(self, element_bytes):
        """Add a pre-built element as raw bytes."""
        self.elements.append(element_bytes)
        self.element_args.append(((element_bytes,), {}))
    
    def clear_elements(self):
        """Remove all elements."""
        self.elements = []
        self.element_args = []
    
    def _pack_count(self, count):
        """Pack count value to bytes."""
        count = max(0, min(count, self.max_count))
        if self.count_size == 1:
            fmt = '<b' if self.count_signed else '<B'
        elif self.count_size == 2:
            fmt = '<h' if self.count_signed else '<H'
        elif self.count_size == 4:
            fmt = '<i' if self.count_signed else '<I'
        else:
            return count.to_bytes(self.count_size, 'little')
        return struct.pack(fmt, count)
    
    def build_normal(self):
        """Build array with correct count."""
        count = len(self.elements)
        count_bytes = self._pack_count(count)
        data_bytes = b"".join(self.elements)
        return count_bytes, data_bytes, f"normal (count={count})"
    
    def fuzz(self, strategy=None):
        """Build array with fuzzing applied."""
        if not self.elements:
            count = choice(self.interesting_counts)
            return self._pack_count(count), b"", f"empty_array (count={count})"
        
        actual_count = len(self.elements)
        data_bytes = b"".join(self.elements)
        
        if strategy is None:
            strategy = choice([
                self.STRATEGY_COUNT_OVERFLOW,
                self.STRATEGY_COUNT_UNDERFLOW,
                self.STRATEGY_ZERO_COUNT,
                self.STRATEGY_HUGE_COUNT,
                self.STRATEGY_COUNT_DELTA,
                self.STRATEGY_DUPLICATE,
                self.STRATEGY_INTEGER_OVERFLOW,
            ])
        
        if strategy == self.STRATEGY_COUNT_OVERFLOW:
            extra = choice([1, 2, 4, 8, 16, 100])
            fuzz_count = min(actual_count + extra, self.max_count)
            return self._pack_count(fuzz_count), data_bytes, f"count_overflow (count={fuzz_count}, actual={actual_count}, +{extra})"
        
        elif strategy == self.STRATEGY_COUNT_UNDERFLOW:
            if actual_count > 1:
                less = choice([1, 2, actual_count - 1])
                less = min(less, actual_count - 1)
                fuzz_count = actual_count - less
            else:
                fuzz_count = 0
            return self._pack_count(fuzz_count), data_bytes, f"count_underflow (count={fuzz_count}, actual={actual_count})"
        
        elif strategy == self.STRATEGY_ZERO_COUNT:
            return self._pack_count(0), data_bytes, f"zero_count (data_len={len(data_bytes)})"
        
        elif strategy == self.STRATEGY_HUGE_COUNT:
            fuzz_count = choice([self.max_count, self.max_count - 1, 0xffff, 0x7fff])
            fuzz_count = min(fuzz_count, self.max_count)
            if randint(0, 1):
                truncated = self.elements[0] if self.elements else b""
                return self._pack_count(fuzz_count), truncated, f"huge_count (count={fuzz_count}, data_len={len(truncated)})"
            return self._pack_count(fuzz_count), data_bytes, f"huge_count (count={fuzz_count}, actual={actual_count})"
        
        elif strategy == self.STRATEGY_COUNT_DELTA:
            delta = choice([-4, -3, -2, -1, 1, 2, 3, 4])
            fuzz_count = max(0, min(actual_count + delta, self.max_count))
            sign = '+' if delta > 0 else ''
            return self._pack_count(fuzz_count), data_bytes, f"count_delta (count={fuzz_count}, delta={sign}{delta})"
        
        elif strategy == self.STRATEGY_DUPLICATE:
            dup_count = choice([2, 3, 4, 8])
            dup_index = randint(0, len(self.elements) - 1)
            duplicated = self.elements[:]
            for _ in range(dup_count):
                duplicated.append(self.elements[dup_index])
            fuzz_type = choice(['correct', 'original', 'overflow'])
            if fuzz_type == 'correct':
                fuzz_count = len(duplicated)
            elif fuzz_type == 'original':
                fuzz_count = actual_count
            else:
                fuzz_count = len(duplicated) + choice([1, 2, 4])
            fuzz_count = min(fuzz_count, self.max_count)
            return self._pack_count(fuzz_count), b"".join(duplicated), f"duplicate (count={fuzz_count}, elements={len(duplicated)})"
        
        elif strategy == self.STRATEGY_INTEGER_OVERFLOW:
            if self.elements:
                avg_elem_size = len(data_bytes) // len(self.elements)
                if avg_elem_size > 0:
                    overflow_count = (0xFFFFFFFF // avg_elem_size) + choice([1, 2, 100])
                    overflow_count = min(overflow_count, self.max_count)
                    return self._pack_count(overflow_count), data_bytes, f"integer_overflow (count={overflow_count}, elem_size≈{avg_elem_size})"
            return self.fuzz(self.STRATEGY_HUGE_COUNT)
        
        fuzz_count = choice(self.interesting_counts)
        return self._pack_count(fuzz_count), data_bytes, f"interesting_count ({fuzz_count})"
    
    def generate_test_cases(self, include_normal=True):
        """Generate all interesting test cases."""
        if include_normal:
            yield self.build_normal()
        
        for strategy in [self.STRATEGY_COUNT_OVERFLOW, self.STRATEGY_COUNT_UNDERFLOW,
                        self.STRATEGY_ZERO_COUNT, self.STRATEGY_HUGE_COUNT,
                        self.STRATEGY_DUPLICATE, self.STRATEGY_INTEGER_OVERFLOW]:
            yield self.fuzz(strategy)
        
        actual_count = len(self.elements)
        for delta in [-4, -3, -2, -1, 1, 2, 3, 4]:
            fuzz_count = max(0, min(actual_count + delta, self.max_count))
            if fuzz_count != actual_count:
                sign = '+' if delta > 0 else ''
                yield self._pack_count(fuzz_count), b"".join(self.elements), f"delta_{sign}{delta} (count={fuzz_count})"
        
        for count in self.interesting_counts:
            yield self._pack_count(count), b"".join(self.elements), f"boundary_count ({count})"


class ProtocolFuzzer:
    """
    Base class for protocol fuzzers.
    
    """
    
    def __init__(self):
        self.fuzzing = False
        self.blind = False
        self.byteflip = False
        self.combined = False
        self.ber_bruteforce = False
        self.ber_boundary = False
        self.ber_double = False
        self.ber_strict = False
        self.fuzz_len = False           # Length/count mismatch testing
        self.fuzz_len_mode = 'standard' # 'standard', 'extended', 'boundary', 'power2'
        self.dry_run = False
        self.fuzz_targets = ['all']
        self.fuzz_fields_count = 1
        self.packet_count = 0
        self.current_fuzzed_fields = {}
        self._fuzz_len_desc = {}
        self._fuzz_field_desc = {}
        self._fuzz_original_values = {}
        self.bit_flip_info = None
        self.blind_mutation_info = None
        self.byteflip_info = None
        self.verbose = False
        self.field_definitions = {}
        self.length_delta_gen = None    # LengthDeltaGenerator instance
        self.fuzzer = Fuzzer()          # Unified fuzzer for all field types
    
    # ========================================================================
    # ABSTRACT METHODS
    # ========================================================================
    
    def get_protocol_name(self):
        raise NotImplementedError()
    
    def get_available_targets(self):
        raise NotImplementedError()
    
    def define_fuzz_fields(self):
        raise NotImplementedError()
    
    def run_fuzzing_session(self):
        raise NotImplementedError()
    
    def build_ber_packet(self):
        raise NotImplementedError("Subclass must implement build_ber_packet() for BER bruteforce")
    
    def send_ber_packet(self, data):
        raise NotImplementedError()
    
    def receive_ber_response(self):
        raise NotImplementedError()
    
    def reconnect_ber(self):
        raise NotImplementedError()
    
    def parse_ber_response(self, response):
        """
        Parse response during BER bruteforce. Override in subclass.
        Return dict with 'status' key for display.
        """
        return {'status': 'UNKNOWN', 'raw_len': len(response) if response else 0}
    
    # ========================================================================
    # FUZZING CORE
    # ========================================================================
    
    def should_fuzz(self, target):
        if not self.fuzzing:
            return False
        if self.dry_run:
            return False
        if self.blind and not self.combined:
            return False
        if self.byteflip:
            return False
        if 'all' in self.fuzz_targets or target in self.fuzz_targets:
            return True
        return False
    
    # ========================================================================
    # LENGTH FIELD FUZZING (--fuzz-len)
    # ========================================================================
    
    def get_length_deltas(self):
        """Get list of length deltas to test."""
        if self.length_delta_gen:
            return self.length_delta_gen.get_deltas()
        return LengthDeltaGenerator.STANDARD_DELTAS
    
    def generate_length_test_cases(self, base_count, item_size=1):
        """
        Generate test cases for length/count mismatch testing.
        
        Args:
            base_count: The actual number of items
            item_size: Size of each item in bytes
        
        Returns:
            List of (test_type, count_delta, length_delta, description) tuples
        """
        if self.length_delta_gen:
            return self.length_delta_gen.generate_test_cases(base_count, item_size)
        
        # Fallback to default implementation
        gen = LengthDeltaGenerator(mode=self.fuzz_len_mode)
        return gen.generate_test_cases(base_count, item_size)
    
    def apply_length_delta(self, value, delta, min_val=0, max_val=0xFFFF):
        """
        Apply delta to a length/count value with bounds checking.
        
        Args:
            value: Original value
            delta: Delta to apply
            min_val: Minimum allowed value (default 0)
            max_val: Maximum allowed value (default 65535 for 2-byte fields)
        
        Returns:
            Bounded result
        """
        return LengthDeltaGenerator.apply_delta(value, delta, min_val, max_val)
    
    def run_fuzz_len_session(self):
        """
        Run length field fuzzing session.
        
        Override this in protocol-specific fuzzers to implement
        count/DataLength mismatch testing.
        
        Default implementation raises NotImplementedError.
        Subclasses should:
        1. Get test cases from generate_length_test_cases()
        2. For each test case, create a packet with the specified mismatches
        3. Send and check for crashes/interesting responses
        """
        raise NotImplementedError(
            "Subclass must implement run_fuzz_len_session() for --fuzz-len mode. "
            "See SMB2Fuzzer._run_overflow_fuzz_len_session() for an example."
        )
    
    # Patterns to identify length/size/count fields (case-insensitive)
    LENGTH_FIELD_PATTERNS = [
        'length', 'size', 'count', 'offset', 'len', 'remaining',
        'datalength', 'bytecount', 'buffersize', 'numbytes',
        'originalpayloadsize', 'originalcompressedsegmentsize',
        'compressionlength', 'writecount', 'readcount',
    ]
    
    def is_length_field(self, field_name):
        """Check if a field name matches length/size/count patterns."""
        name_lower = field_name.lower()
        for pattern in self.LENGTH_FIELD_PATTERNS:
            if pattern in name_lower:
                return True
        return False
    
    def get_length_fields_from_dict(self, available_fields):
        """
        Extract length/size/count fields from a dictionary of available fuzz fields.
        
        Args:
            available_fields: Dict of field_name -> fuzz_function
            
        Returns:
            Dict of length field names -> fuzz_functions
        """
        length_fields = {}
        for field_name, fuzz_func in available_fields.items():
            if self.is_length_field(field_name):
                length_fields[field_name] = fuzz_func
        return length_fields
    
    def generate_fuzz_len_value(self, base_value, field_size=4):
        """
        Generate a fuzzed length value by applying a small delta.
        
        Uses the configured fuzz_len_mode deltas (standard/extended/boundary/power2).
        
        Args:
            base_value: The correct/expected value
            field_size: Size of field in bytes (1, 2, 4, or 8)
            
        Returns:
            Tuple of (fuzz_bytes, description)
        """
        from random import choice
        
        # Get deltas from generator (or create one if needed)
        if self.length_delta_gen:
            deltas = self.length_delta_gen.get_deltas()
        else:
            deltas = LengthDeltaGenerator(mode=self.fuzz_len_mode).get_deltas()
        
        delta = choice(deltas)
        
        # Apply delta, ensure non-negative
        max_val = {1: 0xFF, 2: 0xFFFF, 4: 0xFFFFFFFF, 8: 0xFFFFFFFFFFFFFFFF}.get(field_size, 0xFFFFFFFF)
        fuzz_value = max(0, base_value + delta) & max_val
        
        # Pack to bytes
        fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(field_size, '<I')
        fuzz_bytes = struct.pack(fmt, fuzz_value)
        
        delta_str = f"+{delta}" if delta > 0 else str(delta)
        description = f"delta {delta_str} (orig={base_value}, fuzzed={fuzz_value})"
        return fuzz_bytes, description
    
    def apply_fuzz_len_to_fields(self, available_fields, base_values=None):
        """
        Apply fuzz-len mode to available fields.
        
        When fuzz_len is enabled, this method:
        1. Identifies length/size/count fields
        2. Picks one randomly
        3. Generates an interesting mismatch value
        
        Args:
            available_fields: Dict of field_name -> fuzz_function
            base_values: Optional dict of field_name -> expected_value for smarter fuzzing
            
        Returns:
            Tuple of (fuzz_fields_dict, fuzz_len_info_string) or (None, None) if no length fields
        """
        if not self.fuzz_len:
            return None, None
        
        length_fields = self.get_length_fields_from_dict(available_fields)
        if not length_fields:
            return None, None
        
        from random import choice
        
        # Pick a length field to fuzz
        target_field = choice(list(length_fields.keys()))
        
        # Determine field size from name heuristics
        field_size = 4  # Default to 4 bytes
        name_lower = target_field.lower()
        if 'offset' in name_lower and 'data' not in name_lower:
            field_size = 2  # Offsets are often 2 bytes
        
        # Get base value if provided, otherwise use a reasonable default
        base_value = 0
        if base_values and target_field in base_values:
            base_value = base_values[target_field]
        else:
            # Try to infer from common field names
            if 'length' in name_lower or 'size' in name_lower:
                base_value = 4096  # Common buffer size
            elif 'count' in name_lower:
                base_value = 1
            elif 'offset' in name_lower:
                base_value = 64  # Common header size
        
        fuzz_bytes, description = self.generate_fuzz_len_value(base_value, field_size)
        
        # Create fuzz_fields dict compatible with existing code
        fuzz_fields = {target_field: (lambda val=fuzz_bytes: val)}
        fuzz_values = {target_field: fuzz_bytes}
        
        self.current_fuzzed_fields = fuzz_values
        self._fuzz_len_info = description
        
        return fuzz_fields, description
    
    def get_fuzz_fields(self, target):
        return self.field_definitions.get(target, {})
    
    def select_fuzz_fields(self, target):
        all_fields = self.get_fuzz_fields(target)
        if not all_fields:
            return {}
        num_to_fuzz = min(self.fuzz_fields_count, len(all_fields))
        field_names = list(all_fields.keys())
        selected = {}
        for _ in range(num_to_fuzz):
            if field_names:
                field_name = choice(field_names)
                field_names.remove(field_name)
                selected[field_name] = all_fields[field_name]
        fuzz_values = {}
        fuzz_descriptions = {}
        for field_name, (size, fmt, mutation_func) in selected.items():
            result = mutation_func(b"")
            # Handle both (bytes, desc) tuple and plain bytes
            if isinstance(result, tuple):
                fuzz_values[field_name] = result[0]
                fuzz_descriptions[field_name] = result[1]
            else:
                fuzz_values[field_name] = result
                fuzz_descriptions[field_name] = None
        self.current_fuzzed_fields = fuzz_values
        self._fuzz_field_desc = fuzz_descriptions
        return fuzz_values
    
    def get_fuzz_value(self, fuzz_fields, field_name, size, fmt, original_value=None):
        if field_name not in fuzz_fields:
            return None
        value = fuzz_fields[field_name]
        # Store original value if provided
        if original_value is not None:
            self._fuzz_original_values[field_name] = original_value
        if len(value) == size:
            return struct.unpack(f'<{fmt}', value)[0]
        if len(value) > size:
            value = value[:size]
        else:
            value = value + b'\x00' * (size - len(value))
        return struct.unpack(f'<{fmt}', value)[0]
    
    def get_fuzz_bytes(self, fuzz_fields, field_name, size, original_value=None):
        if field_name not in fuzz_fields:
            return None
        # Store original value if provided
        if original_value is not None:
            self._fuzz_original_values[field_name] = f"({len(original_value)} bytes)"
        return fuzz_fields[field_name]
    
    # ========================================================================
    # BLIND FUZZING
    # ========================================================================
    
    def apply_blind_mutations(self, data, packet_type=None):
        if len(data) == 0:
            return data
        strategies = ['bit_flip', 'byte_flip', 'known_integers', 'random_bytes', 'repeat_bytes', 'delete_bytes', 'insert_bytes']
        strategy = choice(strategies)
        data = bytearray(data)
        mutation_info = {'strategy': strategy, 'details': []}
        
        if strategy == 'bit_flip':
            num_flips = randint(1, min(8, len(data) * 8))
            for _ in range(num_flips):
                byte_pos = randint(0, len(data) - 1)
                bit_pos = randint(0, 7)
                data[byte_pos] ^= (1 << bit_pos)
                mutation_info['details'].append(f"Flipped bit {bit_pos} at offset {byte_pos}")
        elif strategy == 'byte_flip':
            num_bytes = randint(1, min(16, len(data)))
            for _ in range(num_bytes):
                pos = randint(0, len(data) - 1)
                data[pos] = randint(0, 255)
                mutation_info['details'].append(f"Random byte at offset {pos}")
        elif strategy == 'known_integers':
            interesting = [0, 1, 0xFF, 0xFFFF, 0xFFFFFFFF, 0x7FFFFFFF, 0x80000000]
            value = choice(interesting)
            if value <= 0xFF:
                size, fmt = 1, 'B'
            elif value <= 0xFFFF:
                size, fmt = 2, 'H'
            else:
                size, fmt = 4, 'I'
            if len(data) >= size:
                pos = randint(0, len(data) - size)
                struct.pack_into(f'<{fmt}', data, pos, value)
                mutation_info['details'].append(f"Interesting integer 0x{value:x} at offset {pos}")
        elif strategy == 'random_bytes':
            chunk_size = randint(1, min(64, len(data)))
            pos = randint(0, len(data) - chunk_size)
            for i in range(chunk_size):
                data[pos + i] = randint(0, 255)
            mutation_info['details'].append(f"Random chunk ({chunk_size} bytes) at offset {pos}")
        elif strategy == 'repeat_bytes':
            byte_val = randint(0, 255)
            chunk_size = randint(1, min(32, len(data)))
            pos = randint(0, len(data) - chunk_size)
            for i in range(chunk_size):
                data[pos + i] = byte_val
            mutation_info['details'].append(f"Repeated 0x{byte_val:02x} ({chunk_size} bytes) at offset {pos}")
        elif strategy == 'delete_bytes':
            if len(data) > 10:
                delete_size = randint(1, min(8, len(data) - 5))
                pos = randint(0, len(data) - delete_size)
                del data[pos:pos + delete_size]
                mutation_info['details'].append(f"Deleted {delete_size} bytes at offset {pos}")
        elif strategy == 'insert_bytes':
            insert_size = randint(1, 16)
            pos = randint(0, len(data))
            insert_data = bytes([randint(0, 255) for _ in range(insert_size)])
            data[pos:pos] = insert_data
            mutation_info['details'].append(f"Inserted {insert_size} random bytes at offset {pos}")
        
        self.blind_mutation_info = mutation_info
        return bytes(data)
    
    def apply_single_bit_flip(self, data):
        if len(data) == 0:
            return data
        data = bytearray(data)
        byte_offset = randint(0, len(data) - 1)
        bit_position = randint(0, 7)
        original = data[byte_offset]
        data[byte_offset] ^= (1 << bit_position)
        self.bit_flip_info = {'offset': byte_offset, 'bit': bit_position, 'original': original, 'flipped': data[byte_offset]}
        return bytes(data)
    
    def apply_byteflip_mutations(self, data, packet_type=None):
        if len(data) == 0:
            return data
        data = bytearray(data)
        num_flips = min(self.fuzz_fields_count, len(data))
        mutations = []
        flipped_offsets = set()
        for _ in range(num_flips):
            offset = randint(0, len(data) - 1)
            attempts = 0
            while offset in flipped_offsets and attempts < 100:
                offset = randint(0, len(data) - 1)
                attempts += 1
            if offset in flipped_offsets:
                continue
            flipped_offsets.add(offset)
            original_byte = data[offset]
            new_byte = randint(0, 255)
            while new_byte == original_byte:
                new_byte = randint(0, 255)
            data[offset] = new_byte
            mutations.append({'offset': offset, 'original': original_byte, 'new': new_byte})
        self.byteflip_info = {'count': len(mutations), 'mutations': mutations}
        return bytes(data)
    
    # ========================================================================
    # DER/ASN.1 BRUTEFORCE
    # ========================================================================
    
    def scan_ber_positions(self, data, strict=False):
        """Scan for DER/ASN.1 fuzzable positions."""
        scanner = DERScanner(strict=strict)
        return scanner.get_fuzzable_positions(data)
    
    def scan_der_structures(self, data, strict=False):
        """Get summary of DER/ASN.1 structures found."""
        scanner = DERScanner(strict=strict)
        return scanner.get_structure_summary(data)
    
    def run_ber_bruteforce_mode(self):
        self.log(f"\n[OffByWon DER] Building base packet...", "ALWAYS")
        try:
            base_packet = self.build_ber_packet()
        except NotImplementedError:
            self.log("[!] DER bruteforce requires build_ber_packet() implementation", "ALWAYS")
            return {'error': 'not_implemented'}
        
        self.log(f"[OffByWon DER] Base packet size: {len(base_packet)} bytes", "ALWAYS")
        
        # Use strict mode if enabled
        strict = getattr(self, 'ber_strict', False)
        positions = self.scan_ber_positions(base_packet, strict=strict)
        self.log(f"[OffByWon DER] Found {len(positions)} fuzzable positions{' (strict mode)' if strict else ''}", "ALWAYS")
        
        for offset, desc in positions[:20]:
            self.log(f"  [{offset:4d}] {desc}", "ALWAYS")
        if len(positions) > 20:
            self.log(f"  ... and {len(positions) - 20} more", "ALWAYS")
        
        if self.dry_run:
            test_count = len(positions) * (8 if self.ber_boundary else 256)
            self.log(f"\n[DRY RUN] Would send {test_count} packets", "ALWAYS")
            return {'positions': len(positions), 'dry_run': True}
        
        if self.ber_boundary:
            test_values = [0x00, 0x01, 0x7E, 0x7F, 0x80, 0x81, 0xFE, 0xFF]
            self.log(f"[OffByWon DER] Boundary mode: {len(test_values)} values per position", "ALWAYS")
        else:
            test_values = list(range(256))
        
        total_tests = len(positions) * len(test_values)
        self.log(f"\n[OffByWon DER] Starting: {total_tests} tests", "ALWAYS")
        
        results = {'positions': len(positions), 'tests_run': 0, 'crashes': [], 'interesting': []}
        test_num = 0
        error_count = 0
        
        try:
            for pos_idx, (offset, desc) in enumerate(positions):
                original_byte = base_packet[offset]
                self.log(f"\n[{pos_idx+1}/{len(positions)}] Testing offset {offset}: {desc}", "ALWAYS")
                
                for test_value in test_values:
                    test_num += 1
                    if test_value == original_byte:
                        continue
                    
                    # Progress indicator every 50 tests
                    if results['tests_run'] > 0 and results['tests_run'] % 50 == 0:
                        self.log(f"  ... {results['tests_run']} tests completed", "ALWAYS")
                    
                    mutated = bytearray(base_packet)
                    mutated[offset] = test_value
                    
                    try:
                        # Reconnect for each test (stateful protocols like LDAP)
                        try:
                            self.reconnect_ber()
                        except:
                            error_count += 1
                            if error_count >= 3:
                                self.log(f"  [!] Too many connection errors, skipping position", "ALWAYS")
                                break
                            continue
                        
                        self.send_ber_packet(bytes(mutated))
                        results['tests_run'] += 1
                        error_count = 0
                        
                        try:
                            response = self.receive_ber_response()
                            parsed = self.parse_ber_response(response)
                            status = parsed.get('status', 'UNKNOWN')
                            
                            if response is None:
                                results['interesting'].append({
                                    'offset': offset, 'value': test_value,
                                    'original': original_byte, 'desc': desc, 'reason': 'no_response'
                                })
                                self.log(f"  [!] 0x{test_value:02x} -> No response", "ALWAYS")
                            elif status not in ('SASL_BIND_IN_PROGRESS', 'PROTOCOL_ERROR', 'OPERATIONS_ERROR'):
                                # Only log unexpected responses
                                self.log(f"  [?] 0x{test_value:02x} -> {status}", "ALWAYS")
                        except KeyboardInterrupt:
                            raise
                        except Exception as e:
                            self.log(f"  [!] Receive error: {e}", "VERBOSE")
                    
                    except KeyboardInterrupt:
                        raise
                    
                    except OSError as e:
                        # Only print CRASH for "No route to host"
                        if e.errno == errno.EHOSTUNREACH:
                            results['crashes'].append({
                                'offset': offset, 'value': test_value,
                                'original': original_byte, 'desc': desc, 'error': str(e)
                            })
                            self.log(f"  [!!!] CRASH? at offset {offset}, value 0x{test_value:02x}: {e}", "ALWAYS")
                            error_count += 1
                        else:
                            # Broken pipe, connection reset - just reconnect silently
                            error_count += 1
                        
                        if error_count < 3:
                            try:
                                self.reconnect_ber()
                                error_count = 0
                            except KeyboardInterrupt:
                                raise
                            except:
                                pass
                        if error_count >= 3:
                            self.log(f"  [!] Too many errors, skipping position", "ALWAYS")
                            break
                    
                    except Exception as e:
                        self.log(f"  [!] Error: {e}", "VERBOSE")
        
        except KeyboardInterrupt:
            self.log(f"\n[OffByWon BER] Interrupted! Tests: {results['tests_run']}", "ALWAYS")
            return results
        
        self.log(f"\n[OffByWon BER] Complete! Tests: {results['tests_run']}, Crashes: {len(results['crashes'])}", "ALWAYS")
        return results
    
    # ========================================================================
    # PACKET HANDLING
    # ========================================================================
    
    def send_packet(self, data, packet_type=None):
        if self.blind and not self.dry_run:
            if packet_type is None or 'all' in self.fuzz_targets or packet_type in self.fuzz_targets:
                data = self.apply_blind_mutations(data, packet_type)
        
        if self.byteflip and not self.dry_run:
            if packet_type is None or 'all' in self.fuzz_targets or packet_type in self.fuzz_targets:
                data = self.apply_byteflip_mutations(data, packet_type)
        
        if self.combined and self.fuzzing and not self.dry_run:
            if packet_type is None or 'all' in self.fuzz_targets or packet_type in self.fuzz_targets:
                data = self.apply_single_bit_flip(data)
        
        self.log_packet(data, packet_type)
        self.current_fuzzed_fields = {}
        self._fuzz_len_desc = {}
        self._fuzz_field_desc = {}
        self._fuzz_original_values = {}
        self.bit_flip_info = None
        self.blind_mutation_info = None
        self.byteflip_info = None
        self._send_packet_impl(data, packet_type)
    
    def _send_packet_impl(self, data, packet_type):
        raise NotImplementedError()
    
    def log_packet(self, data, packet_type):
        self.packet_count += 1
        print(f"{'='*70}")
        print(f"[OffByWon] PACKET #{self.packet_count} ({len(data)} bytes)")
        if packet_type:
            print(f"Type: {packet_type}")
        if self.dry_run:
            print("Mode: CLEAN (verification)")
        if self.blind and self.blind_mutation_info:
            info = self.blind_mutation_info
            print(f"Blind mutation: {info['strategy']}")
            for detail in info['details']:
                print(f"  {detail}")
        if self.byteflip and self.byteflip_info:
            info = self.byteflip_info
            print(f"Byteflip: {info['count']} bytes")
            for m in info['mutations']:
                print(f"  Offset {m['offset']:4d}: 0x{m['original']:02x} -> 0x{m['new']:02x}")
        if self.current_fuzzed_fields:
            print(f"Fuzzed fields: {list(self.current_fuzzed_fields.keys())}")
            for field_name, value in self.current_fuzzed_fields.items():
                orig = self._fuzz_original_values.get(field_name)
                desc = self._fuzz_field_desc.get(field_name, "")
                
                # --fuzz-len mode has its own description format
                if field_name in self._fuzz_len_desc:
                    print(f"  → {field_name} = {self._fuzz_len_desc[field_name]}")
                # Numeric fields: show original → 0xhex
                elif isinstance(orig, int) and len(value) <= 8:
                    fmt = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}.get(len(value), '<I')
                    try:
                        fuzzed_val = struct.unpack(fmt, value.ljust(len(value), b'\x00'))[0]
                        print(f"  → {field_name} = {orig} → 0x{fuzzed_val:x}")
                    except:
                        print(f"  → {field_name} = {orig} → {value.hex()}")
                # String/bytes fields with original and description
                elif orig is not None:
                    if desc:
                        print(f"  → {field_name} = {orig} → ({len(value)} bytes) [{desc}]")
                    else:
                        print(f"  → {field_name} = {orig} → ({len(value)} bytes)")
                # No original available
                elif desc:
                    print(f"  → {field_name} = ({len(value)} bytes) [{desc}]")
                else:
                    print(f"  → {field_name} = {value.hex() if len(value) <= 32 else f'({len(value)} bytes)'}")
        if self.bit_flip_info:
            info = self.bit_flip_info
            print(f"Byte flip:")
            print(f"  → offset {info['offset']} (0x{info['original']:02x} → 0x{info['flipped']:02x})")
        print(f"{'='*70}")
        # Print FULL packet hex
        print(f"Hex: {data.hex()}")
        print(f"{'='*70}\n")
    
    # ========================================================================
    # CLI
    # ========================================================================
    
    def add_protocol_arguments(self, parser):
        pass
    
    def setup_argument_parser(self):
        parser = argparse.ArgumentParser(
            description=f'OffByWon Fuzzing Framework - {self.get_protocol_name()}',
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=f"""
OffByWon Fuzzing Framework
Author: Laurent Gaffié
Website: https://secorizon.com
Twitter: @secorizon
            """
        )
        
        protocol_group = parser.add_argument_group('Protocol Options')
        self.add_protocol_arguments(protocol_group)
        
        fuzz_group = parser.add_argument_group('Fuzzing Options')
        fuzz_group.add_argument('-f', '--fuzz', action='store_true', dest='fuzzing', help='Enable field-level fuzzing')
        fuzz_group.add_argument('--fuzz-target', action='append', dest='fuzz_targets',
                               choices=self.get_available_targets() + ['all'], help='Target to fuzz')
        fuzz_group.add_argument('--fuzz-count', type=int, default=1, dest='fuzz_fields_count', help='Fields to fuzz per packet')
        fuzz_group.add_argument('--blind', action='store_true', help='Blind fuzzing mode')
        fuzz_group.add_argument('--byteflip', action='store_true', help='Byteflip mode')
        fuzz_group.add_argument('--combined', action='store_true', help='Combined fuzzing')
        fuzz_group.add_argument('--ber-bruteforce', action='store_true', dest='ber_bruteforce', help='DER/ASN.1 bruteforce')
        fuzz_group.add_argument('--ber-boundary', action='store_true', dest='ber_boundary', help='DER boundary values only (0x00,0x7F,0x80,0xFF)')
        fuzz_group.add_argument('--ber-strict', action='store_true', dest='ber_strict', help='DER strict mode (fewer false positives)')
        fuzz_group.add_argument('--ber-double', action='store_true', dest='ber_double', help='DER double position testing')
        fuzz_group.add_argument('--fuzz-len', action='store_true', dest='fuzz_len',
                               help='Length/count mismatch testing (+/-1 to +/-4 deltas)')
        fuzz_group.add_argument('--fuzz-len-mode', choices=['standard', 'extended', 'boundary', 'power2'],
                               default='standard', dest='fuzz_len_mode',
                               help='Fuzz-len delta mode: standard (+/-1-4), extended (+/-1-8), '
                                    'boundary (+/-1 only), power2 (alignment boundaries)')
        fuzz_group.add_argument('--dry-run', action='store_true', help='Send clean unfuzzed packets to verify connectivity')
        fuzz_group.add_argument('-n', '--num-iterations', type=int, default=None, help='Number of iterations')
        parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
        
        return parser
    
    def parse_arguments(self, args=None):
        parser = self.setup_argument_parser()
        parsed = parser.parse_args(args)
        
        self.fuzzing = parsed.fuzzing
        self.blind = parsed.blind
        self.byteflip = parsed.byteflip
        self.combined = parsed.combined
        self.ber_bruteforce = getattr(parsed, 'ber_bruteforce', False)
        self.ber_boundary = getattr(parsed, 'ber_boundary', False)
        self.ber_double = getattr(parsed, 'ber_double', False)
        self.ber_strict = getattr(parsed, 'ber_strict', False)
        self.fuzz_len = getattr(parsed, 'fuzz_len', False)
        self.fuzz_len_mode = getattr(parsed, 'fuzz_len_mode', 'standard')
        self.dry_run = parsed.dry_run
        self.verbose = parsed.verbose
        self.fuzz_fields_count = parsed.fuzz_fields_count
        self.fuzz_targets = parsed.fuzz_targets or ['all']
        
        # Auto-enable fuzzing if --fuzz-target explicitly specified
        if parsed.fuzz_targets and not self.fuzzing:
            self.fuzzing = True
        
        # Initialize fuzzer with correct mode
        self.fuzzer = Fuzzer(mode=self.fuzz_len_mode)
        
        # Initialize length delta generator for --fuzz-len mode
        if self.fuzz_len:
            self.length_delta_gen = LengthDeltaGenerator(mode=self.fuzz_len_mode)
        
        if self.combined and not self.fuzzing:
            print("Error: --combined requires -f")
            sys.exit(1)
        
        return parsed
    
    def log(self, message, level="INFO"):
        if level == "ALWAYS":
            print(message, flush=True)
        elif level == "VERBOSE" and self.verbose:
            print(message, flush=True)
        elif level == "INFO" and not self.dry_run:
            print(message, flush=True)
    
    def run(self, args=None):
        parsed_args = self.parse_arguments(args)
        self.define_fuzz_fields()
        
        if self.ber_bruteforce:
            print(f"[OffByWon] DER/ASN.1 Bruteforce mode")
            return self.run_ber_bruteforce_mode()
        
        if self.fuzz_len:
            print(f"[OffByWon] Length/Count Mismatch mode (deltas: {self.get_length_deltas()})")
            # Note: run_fuzz_len_session() is called by subclass in run_fuzzing_session()
        
        num_iterations = getattr(parsed_args, 'num_iterations', None)
        
        if num_iterations is None:
            iteration = 0
            print(f"[OffByWon] Starting fuzzing (Ctrl+C to stop)...\n")
            while True:
                iteration += 1
                try:
                    self.run_fuzzing_session()
                except KeyboardInterrupt:
                    print(f"\n[OffByWon] Stopped after {iteration} iterations")
                    break
                except (TimeoutError, socket.timeout) as e:
                    print(f"[OffByWon] Connection timeout, retrying...")
                    time.sleep(0.5)
                    continue
                except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as e:
                    print(f"[OffByWon] Connection error: {e}, retrying...")
                    time.sleep(0.5)
                    continue
                except Exception as e:
                    print(f"\n[OffByWon] Error in iteration {iteration}: {e}")
                    if not self.fuzzing:
                        raise
                    time.sleep(0.5)
                    continue
        else:
            for iteration in range(num_iterations):
                if num_iterations > 1:
                    print(f"\n{'='*70}")
                    print(f"[OffByWon] ITERATION {iteration + 1}/{num_iterations}")
                    print(f"{'='*70}\n")
                try:
                    self.run_fuzzing_session()
                except KeyboardInterrupt:
                    print("\n[OffByWon] Interrupted")
                    break
                except (TimeoutError, socket.timeout) as e:
                    print(f"[OffByWon] Connection timeout, retrying...")
                    time.sleep(0.5)
                    continue
                except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, OSError) as e:
                    print(f"[OffByWon] Connection error: {e}, retrying...")
                    time.sleep(0.5)
                    continue
                except Exception as e:
                    print(f"\n[OffByWon] Error: {e}")
                    if not self.fuzzing:
                        raise
                    time.sleep(0.5)
                    continue
        
        print(f"\n[OffByWon] Complete. Sent {self.packet_count} packets.")


def print_banner():
    print("""
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║   ██████╗ ███████╗███████╗██████╗ ██╗   ██╗██╗    ██╗ ██████╗ ███╗   ██╗  ║
║  ██╔═══██╗██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝██║    ██║██╔═══██╗████╗  ██║  ║
║  ██║   ██║█████╗  █████╗  ██████╔╝ ╚████╔╝ ██║ █╗ ██║██║   ██║██╔██╗ ██║  ║
║  ██║   ██║██╔══╝  ██╔══╝  ██╔══██╗  ╚██╔╝  ██║███╗██║██║   ██║██║╚██╗██║  ║
║  ╚██████╔╝██║     ██║     ██████╔╝   ██║   ╚███╔███╔╝╚██████╔╝██║ ╚████║  ║
║   ╚═════╝ ╚═╝     ╚═╝     ╚═════╝    ╚═╝    ╚══╝╚══╝  ╚═════╝ ╚═╝  ╚═══╝  ║
║                                                                           ║
║               Finding bugs at the boundaries others miss                  ║
║                                                                           ║
║   Author: Laurent Gaffié                                                  ║
║   Website: https://secorizon.com                                          ║
║   Twitter: @secorizon                                                     ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
""")


if __name__ == "__main__":
    print_banner()
    print("This is the base framework - import and subclass ProtocolFuzzer.")
    print("\nSee smb311_negotiate_fuzzer.py for an example implementation.")
