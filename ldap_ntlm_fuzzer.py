#!/usr/bin/env python3
"""
LDAP NTLM Authentication Fuzzer
================================

A clean example demonstrating how to build a protocol fuzzer using the
OffByWon framework. This fuzzer targets LDAP servers using NTLM authentication.

This example shows:
1. How to subclass ProtocolFuzzer
2. How to define fuzz fields using FieldType
3. How to use the Fuzzer class for mutations
4. How to implement the required abstract methods
5. How to handle multi-step authentication protocols

Protocol Flow:
    Client                          Server
      |                               |
      |--- NTLM Type 1 (Negotiate) -->|
      |                               |
      |<-- NTLM Type 2 (Challenge) ---|
      |                               |
      |--- NTLM Type 3 (Auth) ------->|
      |                               |
      |<-- Bind Response -------------|

OffByWon Fuzzing Framework
Author: Laurent Gaffié
Website: https://secorizon.com
Twitter: @secorizon

Usage:
    # Basic NTLM bind (no fuzzing, verify connectivity and packet integrity)
    python3 ldap_ntlm_fuzzer.py -s -s 192.168.8.109 --username 'testing' --password 'test' --domain smb3 --dry-run -n1

    # Structured fuzz on NTLM Type 1 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target ntlm_type1

    # Structured fuzz on NTLM Type 3 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target ntlm_type3

    # Structured fuzz all NTLM messages
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-target all

    # Structured Length mismatch testing on NTLM messages
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --fuzz-len --fuzz-target all

    # Blind fuzzing (random mutations) (truncate/insert bytes at random offsets, etc)
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --blind
    
    # Structured fuzzing with a bit of chaops (structured field testing + byte flip)
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' -f --combined --fuzz-target ntlm_type1

    # 2 Byte flip only NTLM Type 3 message
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --fuzz-target ntlm_type3 --fuzz-count 2 --byteflip

    # DER/ASN scan on LDAP NTLM structure + byte flip bruteforce (all discovered DER/ASN are going to be BF x char(0-256))
    # Set a short timeout to close the connection when the server doesn't answer the request..
    python3 ldap_ntlm_fuzzer.py -s 192.168.1.100 --username 'testing' --password 'test' --fuzz-target ntlm_type3 --ber-bruteforce --timeout 0.3
"""

import socket
import struct
import hashlib
import hmac
import os
import time
from random import choice

# =============================================================================
# IMPORT THE OFFBYWON FRAMEWORK
# =============================================================================
# The framework provides all the building blocks we need:
# - ProtocolFuzzer: Base class for our fuzzer
# - FieldType: Constants defining what kind of data each field contains
# - Fuzzer: The mutation engine that generates fuzzed values
# - print_banner: Prints the OffByWon ASCII banner

from offbywon import (
    ProtocolFuzzer,
    FieldType,
    Fuzzer,
    print_banner,
)


class LDAPNTLMFuzzer(ProtocolFuzzer):
    """
    LDAP NTLM Authentication Fuzzer.
    
    This class demonstrates how to build a protocol fuzzer by:
    1. Subclassing ProtocolFuzzer
    2. Implementing the required abstract methods
    3. Defining fuzz fields with proper FieldType annotations
    4. Using the framework's Fuzzer class for mutations
    
    The fuzzer targets LDAP servers using NTLM (SASL GSS-SPNEGO) authentication.
    """
    
    # =========================================================================
    # INITIALIZATION
    # =========================================================================
    
    def __init__(self):
        """
        Initialize the fuzzer.
        
        Call super().__init__() first - this sets up:
        - self.fuzzing (bool): Whether fuzzing is enabled
        - self.fuzzer (Fuzzer): The mutation engine instance
        - self.packet_count (int): Packet counter
        - self.fuzz_targets (list): Which targets to fuzz
        - And many other useful attributes
        """
        super().__init__()
        
        # Connection settings
        self.host = None
        self.port = 389  # Default LDAP port
        self.sock = None
        self.timeout = 5.0
        
        # NTLM credentials
        self.domain = "WORKGROUP"
        self.username = "administrator"
        self.password = "password"
        self.workstation = "FUZZER"
        
        # LDAP state
        self.message_id = 1
        
        # Fuzz-len mode state
        self._fuzz_len_override = None
    
    # =========================================================================
    # REQUIRED ABSTRACT METHODS
    # =========================================================================
    # These methods MUST be implemented - the framework calls them
    
    def get_protocol_name(self):
        """
        Return the protocol name for display.
        
        This is shown in the CLI help and log messages.
        """
        return "LDAP-NTLM"
    
    def get_available_targets(self):
        """
        Return list of fuzz targets.
        
        These are the packet types or protocol phases that can be fuzzed.
        Users can select targets with --fuzz-target <name>.
        """
        return [
            "ntlm_type1",   # NTLM Negotiate message
            "ntlm_type3",   # NTLM Authenticate message
        ]
    
    def define_fuzz_fields(self):
        """
        Define which fields can be fuzzed for each target.
        
        The framework expects field definitions in format:
            {field_name: (size, struct_fmt, mutation_func)}
        
        Where mutation_func takes original bytes and returns (fuzzed_bytes, description).
        We use self.fuzzer methods to create appropriate mutations.
        """
        
        # Helper to create mutation functions for each field type
        def make_int_fuzzer(size):
            """Create integer field fuzzer."""
            def fuzz_int(original):
                fuzzed, desc = self.fuzzer.fuzz(FieldType.INT, 0, size)
                return fuzzed, desc
            return fuzz_int
        
        def make_length_fuzzer(size):
            """Create length field fuzzer (off-by-one targets)."""
            def fuzz_length(original):
                fuzzed, desc = self.fuzzer.fuzz(FieldType.LENGTH, 0, size)
                return fuzzed, desc
            return fuzz_length
        
        def make_offset_fuzzer(size):
            """Create offset field fuzzer."""
            def fuzz_offset(original):
                fuzzed, desc = self.fuzzer.fuzz(FieldType.OFFSET, 0, size)
                return fuzzed, desc
            return fuzz_offset
        
        def make_bytes_fuzzer(size):
            """Create bytes field fuzzer."""
            def fuzz_bytes(original):
                fuzzed, desc = self.fuzzer.fuzz(FieldType.BYTES, b"\x00" * (size or 8))
                return fuzzed, desc
            return fuzz_bytes
        
        def make_string_fuzzer():
            """Create string field fuzzer."""
            def fuzz_string(original):
                fuzzed, desc = self.fuzzer.fuzz(FieldType.STRING, b"")
                return fuzzed, desc
            return fuzz_string
        
        def make_utf16_string_fuzzer():
            """Create UTF-16LE string field fuzzer for NTLM fields."""
            def fuzz_utf16_string(original):
                from random import choice, randint
                
                strategies = [
                    'long_string',
                    'format_string', 
                    'null_chars',
                    'path_traversal',
                    'special_chars',
                    'empty',
                ]
                
                strategy = choice(strategies)
                
                if strategy == 'long_string':
                    length = randint(100, 2000)
                    text = 'A' * length
                    fuzzed = text.encode('utf-16-le')
                    desc = f"long_utf16 ({length} chars)"
                
                elif strategy == 'format_string':
                    patterns = ['%s%s%s%s%s', '%x%x%x%x', '%n%n%n%n', '%.1024d', '%p%p%p%p']
                    text = choice(patterns)
                    fuzzed = text.encode('utf-16-le')
                    desc = f"format_utf16 ({text})"
                
                elif strategy == 'null_chars':
                    # Embed nulls in string
                    text = 'A\x00B\x00C\x00D'
                    fuzzed = text.encode('utf-16-le')
                    desc = "null_embedded_utf16"
                
                elif strategy == 'path_traversal':
                    patterns = ['..\\', '../', '....//']
                    pattern = choice(patterns)
                    reps = randint(10, 50)
                    text = pattern * reps
                    fuzzed = text.encode('utf-16-le')
                    desc = f"path_traversal_utf16 ({reps} reps)"
                
                elif strategy == 'special_chars':
                    # Unicode special chars that might cause issues
                    special = ['\uffff', '\ufffe', '\ud800', '\udfff', '\u0000', '\u202e']
                    text = ''.join([choice(special) for _ in range(randint(10, 50))])
                    try:
                        fuzzed = text.encode('utf-16-le', errors='surrogatepass')
                    except:
                        fuzzed = b'\xff\xfe' * 20
                    desc = f"special_utf16 ({len(text)} chars)"
                
                else:  # empty
                    fuzzed = b""
                    desc = "empty_utf16"
                
                return fuzzed, desc
            return fuzz_utf16_string
        
        # ---------------------------------------------------------------------
        # NTLM Type 1 (Negotiate) Fields
        # ---------------------------------------------------------------------
        # Format: {field_name: (size, struct_fmt, mutation_func)}
        
        self.field_definitions["ntlm_type1"] = {
            # BER/ASN.1 tags
            "SequenceTag": (1, 'B', make_int_fuzzer(1)),
            "BindRequestTag": (1, 'B', make_int_fuzzer(1)),
            "SASLTag": (1, 'B', make_int_fuzzer(1)),
            
            # LDAP message fields
            "MessageID": (4, 'I', make_int_fuzzer(4)),
            "LDAPVersion": (1, 'B', make_int_fuzzer(1)),
            
            # NTLM message structure
            "NTLMSignature": (8, None, make_bytes_fuzzer(8)),
            "NTLMMessageType": (4, 'I', make_int_fuzzer(4)),
            "NTLMFlags": (4, 'I', make_int_fuzzer(4)),
            
            # Domain name security buffer - LENGTH fields are key for off-by-one
            "DomainNameLen": (2, 'H', make_length_fuzzer(2)),
            "DomainNameMaxLen": (2, 'H', make_length_fuzzer(2)),
            "DomainNameOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Workstation security buffer
            "WorkstationLen": (2, 'H', make_length_fuzzer(2)),
            "WorkstationMaxLen": (2, 'H', make_length_fuzzer(2)),
            "WorkstationOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Payload data - NTLM uses UTF-16LE for strings
            "DomainName": (None, None, make_utf16_string_fuzzer()),
            "Workstation": (None, None, make_utf16_string_fuzzer()),
        }
        
        # ---------------------------------------------------------------------
        # NTLM Type 3 (Authenticate) Fields
        # ---------------------------------------------------------------------
        # This message has many length/offset fields - prime targets!
        
        self.field_definitions["ntlm_type3"] = {
            # BER/ASN.1 tags
            "SequenceTag": (1, 'B', make_int_fuzzer(1)),
            "CredentialsTag": (1, 'B', make_int_fuzzer(1)),
            
            # LDAP message
            "MessageID": (4, 'I', make_int_fuzzer(4)),
            
            # NTLM header
            "NTLMSignature": (8, None, make_bytes_fuzzer(8)),
            "NTLMMessageType": (4, 'I', make_int_fuzzer(4)),
            "NTLMFlags": (4, 'I', make_int_fuzzer(4)),
            
            # LM Challenge Response
            "LmResponseLen": (2, 'H', make_length_fuzzer(2)),
            "LmResponseMaxLen": (2, 'H', make_length_fuzzer(2)),
            "LmResponseOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # NT Challenge Response
            "NtResponseLen": (2, 'H', make_length_fuzzer(2)),
            "NtResponseMaxLen": (2, 'H', make_length_fuzzer(2)),
            "NtResponseOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Domain name
            "DomainNameLen": (2, 'H', make_length_fuzzer(2)),
            "DomainNameMaxLen": (2, 'H', make_length_fuzzer(2)),
            "DomainNameOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # User name
            "UserNameLen": (2, 'H', make_length_fuzzer(2)),
            "UserNameMaxLen": (2, 'H', make_length_fuzzer(2)),
            "UserNameOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Workstation name
            "WorkstationLen": (2, 'H', make_length_fuzzer(2)),
            "WorkstationMaxLen": (2, 'H', make_length_fuzzer(2)),
            "WorkstationOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Session key
            "SessionKeyLen": (2, 'H', make_length_fuzzer(2)),
            "SessionKeyMaxLen": (2, 'H', make_length_fuzzer(2)),
            "SessionKeyOffset": (4, 'I', make_offset_fuzzer(4)),
            
            # Payload data - NTLM uses UTF-16LE for strings
            "LmResponse": (None, None, make_bytes_fuzzer(24)),
            "NtResponse": (None, None, make_bytes_fuzzer(None)),
            "DomainName": (None, None, make_utf16_string_fuzzer()),
            "UserName": (None, None, make_utf16_string_fuzzer()),
            "Workstation": (None, None, make_utf16_string_fuzzer()),
            "SessionKey": (None, None, make_bytes_fuzzer(16)),
        }
    
    def run_fuzzing_session(self):
        """
        Run one fuzzing iteration.
        
        This method is called repeatedly by the framework's main loop.
        It should:
        1. Connect to the target (if not connected)
        2. Build and send packets (with fuzzing applied based on settings)
        3. Check responses for interesting behavior
        
        The framework handles:
        - Iteration counting
        - Keyboard interrupt (Ctrl+C)
        - Connection errors (with automatic retry)
        """
        # If fuzz-len mode, use specialized length mismatch testing
        if self.fuzz_len:
            return self.run_fuzz_len_session()
        
        # Ensure we're connected
        if not self.sock:
            self.connect()
        
        # Perform NTLM authentication
        success = self._do_ntlm_auth()
        
        if success:
            self.log("[✓] NTLM authentication completed", "ALWAYS")
        else:
            self.log("[✗] NTLM authentication failed", "ALWAYS")
        
        # Disconnect after each session (fresh connection per iteration)
        self.disconnect()
    
    def run_fuzz_len_session(self):
        """
        Run length mismatch fuzzing session.
        
        This mode specifically tests off-by-one and length/data mismatch bugs
        by sending packets where length fields don't match actual data.
        """
        # Get the length deltas to test
        deltas = self.get_length_deltas()
        
        # Length fields in NTLM that are good targets
        all_length_targets = [
            ("ntlm_type1", "DomainNameLen", 2),
            ("ntlm_type1", "DomainNameMaxLen", 2),
            ("ntlm_type1", "WorkstationLen", 2),
            ("ntlm_type1", "WorkstationMaxLen", 2),
            ("ntlm_type3", "LmResponseLen", 2),
            ("ntlm_type3", "NtResponseLen", 2),
            ("ntlm_type3", "DomainNameLen", 2),
            ("ntlm_type3", "UserNameLen", 2),
            ("ntlm_type3", "WorkstationLen", 2),
            ("ntlm_type3", "SessionKeyLen", 2),
        ]
        
        # Filter by --fuzz-target
        if 'all' in self.fuzz_targets:
            length_targets = all_length_targets
        else:
            length_targets = [t for t in all_length_targets if t[0] in self.fuzz_targets]
        
        if not length_targets:
            self.log("[!] No length fields match --fuzz-target", "ALWAYS")
            return
        
        # Pick a random length field and delta
        target_msg, field_name, field_size = choice(length_targets)
        delta = choice(deltas)
        
        # Store the length override for use in packet building
        self._fuzz_len_override = {
            'target': target_msg,
            'field': field_name,
            'delta': delta,
            'size': field_size,
        }
        
        # Connect and run auth
        if not self.sock:
            self.connect()
        
        success = self._do_ntlm_auth()
        
        if success:
            self.log("[✓] NTLM auth completed (length mismatch accepted!)", "ALWAYS")
        else:
            self.log("[✗] NTLM auth failed", "VERBOSE")
        
        # Clear override
        self._fuzz_len_override = None
        
        self.disconnect()
    
    def _send_packet_impl(self, data, packet_type):
        """
        Actually send the packet over the network.
        
        This is called by self.send_packet() after it applies any
        blind/byteflip mutations and logs the packet.
        
        Args:
            data: The packet bytes to send
            packet_type: String identifying the packet type (for logging)
        """
        if not self.sock:
            self.connect()
        self.sock.sendall(data)
    
    # =========================================================================
    # PROTOCOL-SPECIFIC ARGUMENTS
    # =========================================================================
    
    def add_protocol_arguments(self, parser):
        """
        Add LDAP/NTLM specific command-line arguments.
        
        The framework automatically adds common arguments like:
        - -f/--fuzz: Enable fuzzing
        - --fuzz-target: Select targets
        - --blind: Blind fuzzing mode
        - --fuzz-len: Length mismatch testing
        - --dry-run: Send clean packets only
        - -n: Number of iterations
        - -v: Verbose output
        
        Here we add protocol-specific arguments.
        """
        # Target specification
        parser.add_argument("-s", "--server", required=True,
                          help="LDAP server hostname or IP")
        parser.add_argument("-p", "--port", type=int, default=389,
                          help="LDAP server port (default: 389)")
        parser.add_argument("--timeout", type=float, default=5.0,
                          help="Socket timeout in seconds (default: 5.0)")
        
        # NTLM credentials
        parser.add_argument("--domain", default="WORKGROUP",
                          help="NTLM domain (default: WORKGROUP)")
        parser.add_argument("--username", default="administrator",
                          help="NTLM username (default: administrator)")
        parser.add_argument("--password", default="password",
                          help="NTLM password (default: password)")
        parser.add_argument("--workstation", default="FUZZER",
                          help="Workstation name (default: FUZZER)")
    
    def parse_arguments(self, args=None):
        """
        Parse arguments and store protocol-specific values.
        
        Always call super().parse_arguments() first - it handles all the
        common framework arguments and returns the parsed namespace.
        """
        # Let the framework parse common arguments
        parsed = super().parse_arguments(args)
        
        # Store our protocol-specific values
        self.host = parsed.server
        self.port = parsed.port
        self.timeout = parsed.timeout
        self.domain = parsed.domain
        self.username = parsed.username
        self.password = parsed.password
        self.workstation = parsed.workstation
        
        return parsed
    
    # =========================================================================
    # CONNECTION HANDLING
    # =========================================================================
    
    def connect(self):
        """Establish TCP connection to the LDAP server."""
        self.log(f"[*] Connecting to {self.host}:{self.port}...", "VERBOSE")
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))
        
        self.log(f"[✓] Connected to {self.host}:{self.port}", "ALWAYS")
    
    def disconnect(self):
        """Close the connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
    
    def receive_response(self, size=8192):
        """
        Receive response from server.
        
        Returns None on timeout (which might indicate a crash!).
        """
        try:
            return self.sock.recv(size)
        except socket.timeout:
            self.log("[!] Timeout waiting for response", "VERBOSE")
            return None
        except Exception as e:
            self.log(f"[!] Receive error: {e}", "VERBOSE")
            return None
    
    # =========================================================================
    # BER/DER BRUTEFORCE METHODS
    # =========================================================================
    
    def build_ber_packet(self):
        """
        Build the base LDAP SASL bind packet for BER bruteforce.
        
        This returns a clean NTLM Type 1 wrapped in LDAP.
        The framework will mutate individual bytes to find parsing bugs.
        """
        # Build a clean Type 1 message (no fuzzing)
        saved_fuzzing = self.fuzzing
        self.fuzzing = False
        
        packet = self.build_ntlm_type1()
        
        self.fuzzing = saved_fuzzing
        return packet
    
    def send_ber_packet(self, data):
        """Send packet for BER bruteforce."""
        try:
            self.sock.sendall(data)
        except Exception as e:
            self.log(f"[!] BER send error: {e}", "VERBOSE")
            raise
    
    def receive_ber_response(self):
        """Receive response for BER bruteforce."""
        return self.receive_response()
    
    def reconnect_ber(self):
        """Reconnect for BER bruteforce (after errors or to reset state)."""
        self.disconnect()
        try:
            self.connect()
        except Exception as e:
            self.log(f"[!] BER reconnect failed: {e}", "VERBOSE")
            raise
    
    def parse_ber_response(self, response):
        """
        Parse LDAP response for BER bruteforce.
        
        Returns dict with 'status' for display.
        Different responses might indicate parsing bugs.
        """
        if response is None:
            return {'status': 'NO_RESPONSE', 'raw_len': 0}
        
        if len(response) == 0:
            return {'status': 'EMPTY', 'raw_len': 0}
        
        result = {'status': 'UNKNOWN', 'raw_len': len(response)}
        
        try:
            # Try to find LDAP result code
            # ENUMERATED (0x0a) followed by length and value
            idx = response.find(b"\x0a\x01")
            if idx >= 0 and idx + 2 < len(response):
                result_code = response[idx + 2]
                
                # LDAP result codes
                ldap_codes = {
                    0: 'SUCCESS',
                    1: 'OPERATIONS_ERROR',
                    2: 'PROTOCOL_ERROR',
                    7: 'AUTH_METHOD_NOT_SUPPORTED',
                    14: 'SASL_BIND_IN_PROGRESS',
                    49: 'INVALID_CREDENTIALS',
                    50: 'INSUFFICIENT_ACCESS',
                    53: 'UNWILLING_TO_PERFORM',
                }
                
                status = ldap_codes.get(result_code, f'LDAP_{result_code}')
                result['status'] = status
                result['result_code'] = result_code
            else:
                # Check if it looks like valid BER
                if response[0] == 0x30:  # SEQUENCE
                    result['status'] = 'BER_SEQUENCE'
                else:
                    result['status'] = f'BYTE_0x{response[0]:02X}'
        except Exception as e:
            result['status'] = f'PARSE_ERROR'
            result['error'] = str(e)
        
        return result
    
    # =========================================================================
    # NTLM AUTHENTICATION IMPLEMENTATION
    # =========================================================================
    
    def _do_ntlm_auth(self):
        """
        Perform complete NTLM authentication.
        
        Returns True on success, False on failure.
        """
        # Step 1: Send NTLM Type 1 (Negotiate)
        self.log("[*] Sending NTLM Type 1 (Negotiate)...", "VERBOSE")
        type1_packet = self.build_ntlm_type1()
        self.send_packet(type1_packet, packet_type="ntlm_type1")
        
        # Receive Type 2 (Challenge)
        response = self.receive_response()
        if not response:
            self.log("[!] No Type 2 response received", "ALWAYS")
            return False
        
        self.log(f"[✓] Received Type 2 (Challenge): {len(response)} bytes", "VERBOSE")
        
        # Parse the challenge from Type 2
        challenge, flags, target_info = self._parse_ntlm_type2(response)
        if challenge is None:
            self.log("[!] Failed to parse NTLM Type 2", "ALWAYS")
            # Continue anyway for fuzzing - use dummy challenge
            challenge = b"\x01\x02\x03\x04\x05\x06\x07\x08"
            target_info = b""
        
        # Step 2: Compute NTLM responses
        nt_hash = self._compute_nt_hash(self.password)
        ntlmv2_hash = self._compute_ntlmv2_hash(nt_hash, self.username, self.domain)
        
        # Create client blob and compute response
        client_blob = self._create_client_blob(challenge, target_info)
        nt_response = self._compute_ntlmv2_response(ntlmv2_hash, challenge, client_blob)
        lm_response = b"\x00" * 24  # LMv2 not needed
        
        # Compute session key
        nt_proof = nt_response[:16]
        session_base_key = hmac.new(ntlmv2_hash, nt_proof, "md5").digest()
        random_session_key = os.urandom(16)
        encrypted_session_key = self._rc4_encrypt(session_base_key, random_session_key)
        
        # Step 3: Send NTLM Type 3 (Authenticate)
        self.log("[*] Sending NTLM Type 3 (Authenticate)...", "VERBOSE")
        type3_packet = self.build_ntlm_type3(
            lm_response, nt_response, encrypted_session_key
        )
        self.send_packet(type3_packet, packet_type="ntlm_type3")
        
        # Receive final response
        response = self.receive_response()
        if response:
            self.log(f"[✓] Received bind response: {len(response)} bytes", "VERBOSE")
            return self._check_bind_result(response)
        else:
            self.log("[!] No bind response", "ALWAYS")
            return False
    
    # =========================================================================
    # PACKET BUILDING WITH FRAMEWORK INTEGRATION
    # =========================================================================
    
    def build_ntlm_type1(self):
        """
        Build LDAP SASL Bind with NTLM Type 1 message.
        
        This demonstrates the key pattern for using the framework:
        1. Check if we should fuzz this target
        2. Get fuzz fields if fuzzing is enabled
        3. For each field, check if it should be fuzzed
        4. Use fuzzed value or default value
        """
        # ---------------------------------------------------------------------
        # STEP 1: Check if we should fuzz and get fuzz values
        # ---------------------------------------------------------------------
        # The framework provides should_fuzz() to check if this target is selected
        # and select_fuzz_fields() to get the actual fuzzed values
        # NOTE: In fuzz-len mode, we skip regular field fuzzing - only apply length deltas
        
        fuzz_fields = {}
        if self.should_fuzz("ntlm_type1") and not self.fuzz_len:
            # select_fuzz_fields returns a dict of {field_name: fuzzed_bytes}
            # It automatically uses the field definitions from define_fuzz_fields()
            fuzz_fields = self.select_fuzz_fields("ntlm_type1")
        
        # ---------------------------------------------------------------------
        # STEP 2: Build the NTLM Type 1 message
        # ---------------------------------------------------------------------
        # For each field, we check if it's in fuzz_fields:
        # - If yes: use the fuzzed value
        # - If no: use the default/correct value
        
        # NTLM Signature - should be "NTLMSSP\x00"
        if "NTLMSignature" in fuzz_fields:
            signature = fuzz_fields["NTLMSignature"][:8].ljust(8, b"\x00")
            self._fuzz_original_values["NTLMSignature"] = "NTLMSSP\\x00"
        else:
            signature = b"NTLMSSP\x00"
        
        # Message Type - should be 1 for Negotiate
        msg_type = self.get_fuzz_value(fuzz_fields, "NTLMMessageType", 4, "I", 1)
        if msg_type is None:
            msg_type = 1
        
        # NTLM Flags - capability negotiation
        # These flags request NTLMv2, Unicode, etc.
        flags = self.get_fuzz_value(fuzz_fields, "NTLMFlags", 4, "I", 0xe2080207)
        if flags is None:
            flags = 0xe2080207  # Standard NTLMv2 flags
        
        # Domain and Workstation data - check for fuzzed values
        if "DomainName" in fuzz_fields:
            domain_bytes = fuzz_fields["DomainName"]
            self._fuzz_original_values["DomainName"] = "(0 bytes)"
        else:
            domain_bytes = b""
        
        if "Workstation" in fuzz_fields:
            workstation_bytes = fuzz_fields["Workstation"]
            self._fuzz_original_values["Workstation"] = "(0 bytes)"
        else:
            workstation_bytes = b""
        
        # Calculate offsets - Type 1 header is 40 bytes (with version)
        header_len = 40
        domain_offset = header_len
        workstation_offset = header_len + len(domain_bytes)
        
        # Build security buffer fields with potential fuzzing
        # For field fuzzing: length should MATCH the actual data (valid packet)
        # For length fuzzing (--fuzz-len): length is explicitly fuzzed to mismatch
        
        def apply_len_override(field_name, value):
            """Apply fuzz-len delta if this field is targeted."""
            if self._fuzz_len_override and self._fuzz_len_override['target'] == 'ntlm_type1' and self._fuzz_len_override['field'] == field_name:
                override = self._fuzz_len_override
                new_val = max(0, min(value + override['delta'], 0xFFFF))
                self.current_fuzzed_fields[field_name] = struct.pack('<H', new_val)
                delta_str = f"{override['delta']:+d}"
                self._fuzz_len_desc[field_name] = f"{value} → {new_val} (delta {delta_str})"
                return new_val
            return value
        
        orig_domain_len = len(domain_bytes)
        orig_workstation_len = len(workstation_bytes)
        
        domain_len = self.get_fuzz_value(fuzz_fields, "DomainNameLen", 2, "H", orig_domain_len)
        if domain_len is None:
            domain_len = orig_domain_len
        domain_len = apply_len_override("DomainNameLen", domain_len)
        
        domain_max_len = self.get_fuzz_value(fuzz_fields, "DomainNameMaxLen", 2, "H", orig_domain_len)
        if domain_max_len is None:
            domain_max_len = orig_domain_len
        domain_max_len = apply_len_override("DomainNameMaxLen", domain_max_len)
        
        domain_off = self.get_fuzz_value(fuzz_fields, "DomainNameOffset", 4, "I", domain_offset)
        if domain_off is None:
            domain_off = domain_offset
        
        workstation_len = self.get_fuzz_value(fuzz_fields, "WorkstationLen", 2, "H", orig_workstation_len)
        if workstation_len is None:
            workstation_len = orig_workstation_len
        workstation_len = apply_len_override("WorkstationLen", workstation_len)
        
        workstation_max_len = self.get_fuzz_value(fuzz_fields, "WorkstationMaxLen", 2, "H", orig_workstation_len)
        if workstation_max_len is None:
            workstation_max_len = orig_workstation_len
        workstation_max_len = apply_len_override("WorkstationMaxLen", workstation_max_len)
        
        workstation_off = self.get_fuzz_value(fuzz_fields, "WorkstationOffset", 4, "I", workstation_offset)
        if workstation_off is None:
            workstation_off = workstation_offset
        
        # Version structure (8 bytes) - Windows 10 Build 17763
        version = struct.pack("<BBHBBBB", 10, 0, 17763, 0, 0, 0, 15)
        
        # Assemble NTLM Type 1 message
        ntlm_type1 = signature
        ntlm_type1 += struct.pack("<I", msg_type)
        ntlm_type1 += struct.pack("<I", flags)
        ntlm_type1 += struct.pack("<HHI", domain_len, domain_max_len, domain_off)
        ntlm_type1 += struct.pack("<HHI", workstation_len, workstation_max_len, workstation_off)
        ntlm_type1 += version
        # Append actual data payload
        ntlm_type1 += domain_bytes
        ntlm_type1 += workstation_bytes
        
        # ---------------------------------------------------------------------
        # STEP 3: Wrap in LDAP SASL Bind Request
        # ---------------------------------------------------------------------
        return self._wrap_in_ldap_sasl_bind(ntlm_type1, fuzz_fields)
    
    def build_ntlm_type3(self, lm_response, nt_response, session_key):
        """
        Build LDAP SASL Bind with NTLM Type 3 message.
        
        This is the most complex message and has many length/offset fields
        that are prime targets for off-by-one fuzzing.
        """
        # Get fuzz fields
        fuzz_fields = {}
        # NOTE: In fuzz-len mode, we skip regular field fuzzing - only apply length deltas
        if self.should_fuzz("ntlm_type3") and not self.fuzz_len:
            fuzz_fields = self.select_fuzz_fields("ntlm_type3")
        
        # NTLM header
        if "NTLMSignature" in fuzz_fields:
            signature = fuzz_fields["NTLMSignature"][:8].ljust(8, b"\x00")
            self._fuzz_original_values["NTLMSignature"] = "NTLMSSP\\x00"
        else:
            signature = b"NTLMSSP\x00"
        
        msg_type = self.get_fuzz_value(fuzz_fields, "NTLMMessageType", 4, "I", 3)
        if msg_type is None:
            msg_type = 3
        
        flags = self.get_fuzz_value(fuzz_fields, "NTLMFlags", 4, "I", 0xe2080207)
        if flags is None:
            flags = 0xe2080207
        
        # Prepare payload data (potentially fuzzed)
        if "LmResponse" in fuzz_fields:
            lm_resp = fuzz_fields["LmResponse"]
            self._fuzz_original_values["LmResponse"] = f"({len(lm_response)} bytes)"
        else:
            lm_resp = lm_response
        
        if "NtResponse" in fuzz_fields:
            nt_resp = fuzz_fields["NtResponse"]
            self._fuzz_original_values["NtResponse"] = f"({len(nt_response)} bytes)"
        else:
            nt_resp = nt_response
        
        orig_domain = self.domain.encode("utf-16-le")
        if "DomainName" in fuzz_fields:
            domain = fuzz_fields["DomainName"]
            self._fuzz_original_values["DomainName"] = f'"{self.domain}" ({len(orig_domain)} bytes)'
        else:
            domain = orig_domain
        
        orig_username = self.username.encode("utf-16-le")
        if "UserName" in fuzz_fields:
            username = fuzz_fields["UserName"]
            self._fuzz_original_values["UserName"] = f'"{self.username}" ({len(orig_username)} bytes)'
        else:
            username = orig_username
        
        orig_workstation = self.workstation.encode("utf-16-le")
        if "Workstation" in fuzz_fields:
            workstation = fuzz_fields["Workstation"]
            self._fuzz_original_values["Workstation"] = f'"{self.workstation}" ({len(orig_workstation)} bytes)'
        else:
            workstation = orig_workstation
        
        if "SessionKey" in fuzz_fields:
            sess_key = fuzz_fields["SessionKey"]
            self._fuzz_original_values["SessionKey"] = f"({len(session_key)} bytes)"
        else:
            sess_key = session_key
        
        # Calculate offsets
        # Header: 8 (sig) + 4 (type) + 6*8 (buffers) + 4 (flags) + 8 (version) = 72
        header_len = 72
        lm_offset = header_len
        nt_offset = lm_offset + len(lm_resp)
        domain_offset = nt_offset + len(nt_resp)
        username_offset = domain_offset + len(domain)
        workstation_offset = username_offset + len(username)
        session_key_offset = workstation_offset + len(workstation)
        
        # Build security buffers with potential fuzzing
        # For field fuzzing: length matches data (valid packet)
        # For --fuzz-len: length field is explicitly fuzzed to create mismatch
        def build_buffer(prefix, data, offset):
            """Helper to build a security buffer with fuzzing support."""
            orig_len = len(data)
            orig_offset = offset
            
            data_len = self.get_fuzz_value(fuzz_fields, f"{prefix}Len", 2, "H", orig_len)
            if data_len is None:
                data_len = orig_len
            
            # Apply fuzz-len delta if targeting this field
            if self._fuzz_len_override and self._fuzz_len_override['target'] == 'ntlm_type3' and self._fuzz_len_override['field'] == f"{prefix}Len":
                override = self._fuzz_len_override
                original_len = data_len
                data_len = max(0, min(data_len + override['delta'], 0xFFFF))
                delta_str = f"{override['delta']:+d}"
                self.current_fuzzed_fields[f"{prefix}Len"] = struct.pack('<H', data_len)
                self._fuzz_len_desc[f"{prefix}Len"] = f"{original_len} → {data_len} (delta {delta_str})"
            
            max_len = self.get_fuzz_value(fuzz_fields, f"{prefix}MaxLen", 2, "H", orig_len)
            if max_len is None:
                max_len = orig_len
            
            off = self.get_fuzz_value(fuzz_fields, f"{prefix}Offset", 4, "I", orig_offset)
            if off is None:
                off = orig_offset
            
            return struct.pack("<HHI", data_len, max_len, off)
        
        lm_buffer = build_buffer("LmResponse", lm_resp, lm_offset)
        nt_buffer = build_buffer("NtResponse", nt_resp, nt_offset)
        domain_buffer = build_buffer("DomainName", domain, domain_offset)
        username_buffer = build_buffer("UserName", username, username_offset)
        workstation_buffer = build_buffer("Workstation", workstation, workstation_offset)
        session_key_buffer = build_buffer("SessionKey", sess_key, session_key_offset)
        
        # Version structure
        version = struct.pack("<BBHBBBB", 10, 0, 17763, 0, 0, 0, 15)
        
        # Assemble NTLM Type 3
        ntlm_type3 = signature
        ntlm_type3 += struct.pack("<I", msg_type)
        ntlm_type3 += lm_buffer
        ntlm_type3 += nt_buffer
        ntlm_type3 += domain_buffer
        ntlm_type3 += username_buffer
        ntlm_type3 += workstation_buffer
        ntlm_type3 += session_key_buffer
        ntlm_type3 += struct.pack("<I", flags)
        ntlm_type3 += version
        
        # Append payload
        ntlm_type3 += lm_resp
        ntlm_type3 += nt_resp
        ntlm_type3 += domain
        ntlm_type3 += username
        ntlm_type3 += workstation
        ntlm_type3 += sess_key
        
        # Wrap in LDAP SASL bind
        return self._wrap_in_ldap_sasl_bind(ntlm_type3, fuzz_fields)
    
    # =========================================================================
    # LDAP/BER ENCODING HELPERS
    # =========================================================================
    
    def _wrap_in_ldap_sasl_bind(self, ntlm_message, fuzz_fields=None):
        """
        Wrap an NTLM message in LDAP SASL bind request.
        
        LDAP uses BER encoding. Structure:
        SEQUENCE {
            MessageID INTEGER,
            BindRequest APPLICATION[0] {
                version INTEGER,
                name OCTET STRING,
                authentication CHOICE {
                    sasl [3] {
                        mechanism OCTET STRING,
                        credentials OCTET STRING
                    }
                }
            }
        }
        """
        fuzz_fields = fuzz_fields or {}
        
        # Message ID
        msg_id = self.get_fuzz_value(fuzz_fields, "MessageID", 4, "I")
        if msg_id is None:
            msg_id = self.message_id
            self.message_id += 1
        
        # LDAP version
        ldap_version = self.get_fuzz_value(fuzz_fields, "LDAPVersion", 1, "B")
        if ldap_version is None:
            ldap_version = 3
        
        # Build from inside out
        # SASL mechanism = "GSS-SPNEGO"
        mechanism = b"GSS-SPNEGO"
        mechanism_field = bytes([0x04]) + self._ber_length(len(mechanism)) + mechanism
        
        # SASL credentials = NTLM message
        credentials_field = bytes([0x04]) + self._ber_length(len(ntlm_message)) + ntlm_message
        
        # SASL authentication [3]
        sasl_tag = self.get_fuzz_value(fuzz_fields, "SASLTag", 1, "B")
        if sasl_tag is None:
            sasl_tag = 0xa3
        sasl_body = mechanism_field + credentials_field
        sasl_auth = bytes([sasl_tag]) + self._ber_length(len(sasl_body)) + sasl_body
        
        # Empty bind DN
        name_field = bytes([0x04, 0x00])
        
        # BindRequest body
        bind_body = bytes([0x02, 0x01, ldap_version & 0xff]) + name_field + sasl_auth
        
        # BindRequest [APPLICATION 0]
        bind_tag = self.get_fuzz_value(fuzz_fields, "BindRequestTag", 1, "B")
        if bind_tag is None:
            bind_tag = 0x60
        bind_request = bytes([bind_tag]) + self._ber_length(len(bind_body)) + bind_body
        
        # MessageID
        msgid_bytes = self._ber_integer(msg_id)
        
        # Outer SEQUENCE
        seq_body = msgid_bytes + bind_request
        seq_tag = self.get_fuzz_value(fuzz_fields, "SequenceTag", 1, "B")
        if seq_tag is None:
            seq_tag = 0x30
        
        return bytes([seq_tag]) + self._ber_length(len(seq_body)) + seq_body
    
    def _ber_length(self, length):
        """Encode length in BER format."""
        if length < 128:
            return bytes([length])
        
        # Multi-byte length
        length_bytes = []
        temp = length
        while temp > 0:
            length_bytes.insert(0, temp & 0xff)
            temp >>= 8
        
        return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)
    
    def _ber_integer(self, value):
        """Encode integer as BER INTEGER."""
        if value == 0:
            return bytes([0x02, 0x01, 0x00])
        
        value_bytes = []
        temp = value
        while temp > 0:
            value_bytes.insert(0, temp & 0xff)
            temp >>= 8
        
        return bytes([0x02, len(value_bytes)]) + bytes(value_bytes)
    
    # =========================================================================
    # NTLM TYPE 2 PARSING
    # =========================================================================
    
    def _parse_ntlm_type2(self, ldap_response):
        """
        Parse NTLM Type 2 (Challenge) from LDAP bind response.
        
        Returns: (challenge, flags, target_info) or (None, None, None) on error
        """
        try:
            # Find NTLMSSP signature
            offset = ldap_response.find(b"NTLMSSP\x00")
            if offset == -1:
                return None, None, None
            
            type2 = ldap_response[offset:]
            if len(type2) < 32:
                return None, None, None
            
            # Verify message type is 2
            msg_type = struct.unpack("<I", type2[8:12])[0]
            if msg_type != 2:
                return None, None, None
            
            # Extract challenge (8 bytes at offset 24)
            challenge = type2[24:32]
            
            # Extract flags (at offset 20)
            flags = struct.unpack("<I", type2[20:24])[0]
            
            # Extract target info if present (offset at bytes 40-48)
            target_info = b""
            if len(type2) >= 48:
                ti_len = struct.unpack("<H", type2[40:42])[0]
                ti_offset = struct.unpack("<I", type2[44:48])[0]
                if ti_offset + ti_len <= len(type2):
                    target_info = type2[ti_offset:ti_offset + ti_len]
            
            self.log(f"[+] Challenge: {challenge.hex()}", "VERBOSE")
            return challenge, flags, target_info
            
        except Exception as e:
            self.log(f"[!] Type 2 parse error: {e}", "VERBOSE")
            return None, None, None
    
    # =========================================================================
    # NTLM CRYPTOGRAPHY
    # =========================================================================
    
    def _md4_pure(self, data):
        """
        Pure Python MD4 implementation.
        
        Used as fallback when OpenSSL doesn't support MD4 (modern systems
        disable legacy algorithms by default).
        """
        def left_rotate(x, n):
            return ((x << n) | (x >> (32 - n))) & 0xffffffff
        
        def F(x, y, z):
            return (x & y) | (~x & z)
        
        def G(x, y, z):
            return (x & y) | (x & z) | (y & z)
        
        def H(x, y, z):
            return x ^ y ^ z
        
        # Initialize hash values
        a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
        
        # Pre-processing: adding padding bits
        msg = bytearray(data)
        msg_len = len(data)
        msg.append(0x80)
        while len(msg) % 64 != 56:
            msg.append(0)
        msg += struct.pack('<Q', msg_len * 8)
        
        # Process each 64-byte chunk
        for chunk_start in range(0, len(msg), 64):
            chunk = msg[chunk_start:chunk_start + 64]
            M = struct.unpack('<16I', chunk)
            
            A, B, C, D = a0, b0, c0, d0
            
            # Round 1
            for i in range(16):
                if i % 4 == 0:
                    A = left_rotate((A + F(B, C, D) + M[i]) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + F(A, B, C) + M[i]) & 0xffffffff, 7)
                elif i % 4 == 2:
                    C = left_rotate((C + F(D, A, B) + M[i]) & 0xffffffff, 11)
                else:
                    B = left_rotate((B + F(C, D, A) + M[i]) & 0xffffffff, 19)
            
            # Round 2
            for i in range(16):
                k = (i % 4) * 4 + i // 4
                if i % 4 == 0:
                    A = left_rotate((A + G(B, C, D) + M[k] + 0x5a827999) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + G(A, B, C) + M[k] + 0x5a827999) & 0xffffffff, 5)
                elif i % 4 == 2:
                    C = left_rotate((C + G(D, A, B) + M[k] + 0x5a827999) & 0xffffffff, 9)
                else:
                    B = left_rotate((B + G(C, D, A) + M[k] + 0x5a827999) & 0xffffffff, 13)
            
            # Round 3
            order = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
            for i in range(16):
                k = order[i]
                if i % 4 == 0:
                    A = left_rotate((A + H(B, C, D) + M[k] + 0x6ed9eba1) & 0xffffffff, 3)
                elif i % 4 == 1:
                    D = left_rotate((D + H(A, B, C) + M[k] + 0x6ed9eba1) & 0xffffffff, 9)
                elif i % 4 == 2:
                    C = left_rotate((C + H(D, A, B) + M[k] + 0x6ed9eba1) & 0xffffffff, 11)
                else:
                    B = left_rotate((B + H(C, D, A) + M[k] + 0x6ed9eba1) & 0xffffffff, 15)
            
            a0 = (a0 + A) & 0xffffffff
            b0 = (b0 + B) & 0xffffffff
            c0 = (c0 + C) & 0xffffffff
            d0 = (d0 + D) & 0xffffffff
        
        return struct.pack('<4I', a0, b0, c0, d0)
    
    def _compute_nt_hash(self, password):
        """Compute NT Hash: MD4(UTF-16LE(password))"""
        password_unicode = password.encode("utf-16-le")
        
        # Try OpenSSL MD4 first (faster)
        try:
            return hashlib.new("md4", password_unicode, usedforsecurity=False).digest()
        except (TypeError, ValueError):
            pass
        
        try:
            return hashlib.new("md4", password_unicode).digest()
        except ValueError:
            pass
        
        # Fallback to pure Python implementation
        return self._md4_pure(password_unicode)
    
    def _compute_ntlmv2_hash(self, nt_hash, username, domain):
        """Compute NTLMv2 Hash: HMAC-MD5(NT_Hash, uppercase(user) + domain)"""
        user_domain = (username.upper() + domain).encode("utf-16-le")
        return hmac.new(nt_hash, user_domain, "md5").digest()
    
    def _create_client_blob(self, server_challenge, target_info):
        """Create NTLMv2 client blob with timestamp."""
        client_challenge = os.urandom(8)
        
        # Windows FILETIME
        unix_time = time.time()
        filetime = int((unix_time + 11644473600) * 10000000)
        
        blob = struct.pack("<BB", 1, 1)       # RespType, HiRespType
        blob += struct.pack("<H", 0)          # Reserved1
        blob += struct.pack("<I", 0)          # Reserved2
        blob += struct.pack("<Q", filetime)   # TimeStamp
        blob += client_challenge              # ClientChallenge
        blob += struct.pack("<I", 0)          # Reserved3
        blob += target_info                   # AvPairs
        blob += struct.pack("<I", 0)          # Reserved4
        
        return blob
    
    def _compute_ntlmv2_response(self, ntlmv2_hash, server_challenge, client_blob):
        """Compute NTLMv2 response."""
        temp = server_challenge + client_blob
        nt_proof = hmac.new(ntlmv2_hash, temp, "md5").digest()
        return nt_proof + client_blob
    
    def _rc4_encrypt(self, key, data):
        """RC4 encryption for session key."""
        # Key scheduling
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        
        # PRGA
        i = j = 0
        result = bytearray()
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            result.append(byte ^ S[(S[i] + S[j]) % 256])
        
        return bytes(result)
    
    # =========================================================================
    # RESPONSE CHECKING
    # =========================================================================
    
    def _check_bind_result(self, response):
        """Check LDAP bind response for success (resultCode = 0)."""
        try:
            # Look for ENUMERATED (0x0a) followed by length 1 and value
            idx = response.find(b"\x0a\x01")
            if idx >= 0 and idx + 2 < len(response):
                result_code = response[idx + 2]
                if result_code == 0:
                    self.log("[+] Authentication SUCCESS!", "ALWAYS")
                    return True
                elif result_code == 14:  # saslBindInProgress (OK for Type 1)
                    return True
                elif result_code == 49:
                    self.log("[!] Authentication FAILED: Invalid credentials", "ALWAYS")
                    return False
                else:
                    self.log(f"[!] LDAP resultCode: {result_code}", "ALWAYS")
                    return False
            return True  # Assume success if we can't parse
        except:
            return True


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point."""
    # Print the OffByWon banner
    print_banner()
    
    # Create and run the fuzzer
    fuzzer = LDAPNTLMFuzzer()
    fuzzer.run()


if __name__ == "__main__":
    main()
