package proxy

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// appendU16BE appends a big-endian uint16 to a byte slice.
//
//nolint:gosec // G115: intentional truncation of shifted integer to bytes
func appendU16BE(b []byte, v int) []byte {
	return binary.BigEndian.AppendUint16(b, uint16(v))
}

// appendU24BE appends a big-endian 24-bit integer (3 bytes) to a byte slice.
//
//nolint:gosec // G115: intentional truncation of shifted integer to bytes
func appendU24BE(b []byte, v int) []byte {
	buf := binary.BigEndian.AppendUint32(nil, uint32(v))
	return append(b, buf[1:]...) // skip first byte (24-bit = last 3 of 4)
}

// buildClientHello constructs a minimal TLS 1.2 ClientHello with the given SNI.
// If sni is empty, no SNI extension is included. If sni is set, a single
// server_name entry with type host_name (0x00) is added.
func buildClientHello(sni string) []byte {
	// Build extensions
	var extensions []byte
	if sni != "" {
		// SNI extension: type(2) + length(2) + list_length(2) + name_type(1) + name_length(2) + name
		nameBytes := []byte(sni)
		nameLen := len(nameBytes)
		listLen := sniEntryHeaderLen + nameLen       // 3 + nameLen
		extDataLen := sniListHeaderLen + listLen     // 2 + listLen
		extLen := tlsExtensionHeaderLen + extDataLen // 4 + extDataLen

		ext := make([]byte, extLen)
		// Extension type: SNI (0x0000)
		ext[0] = 0x00
		ext[1] = 0x00
		// Extension data length
		binary.BigEndian.PutUint16(ext[2:4], uint16(extDataLen)) //nolint:gosec // test values always < 256
		// Server name list length
		binary.BigEndian.PutUint16(ext[4:6], uint16(listLen)) //nolint:gosec // test values always < 256
		// Name type: host_name (0x00)
		ext[6] = sniTypeHostName
		// Name length
		binary.BigEndian.PutUint16(ext[7:9], uint16(nameLen)) //nolint:gosec // test values always < 256
		copy(ext[9:], nameBytes)

		extensions = ext
	}

	// ClientHello body: version(2) + random(32) + session_id_len(1) +
	// cipher_suites_len(2) + cipher_suite(2) + compression_len(1) + compression(1) + extensions
	var chBody []byte
	// Client version: TLS 1.2 (0x0303)
	chBody = append(chBody, 0x03, 0x03)
	// Random: 32 zero bytes
	chBody = append(chBody, make([]byte, 32)...)
	// Session ID length: 0
	chBody = append(chBody, 0x00)
	// Cipher suites: length=2, one suite (TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009C)
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C)
	// Compression methods: length=1, null (0x00)
	chBody = append(chBody, 0x01, 0x00)

	if len(extensions) > 0 {
		chBody = appendU16BE(chBody, len(extensions))
		chBody = append(chBody, extensions...)
	}

	// Handshake header: type=ClientHello(0x01) + length(3)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	// Record layer: type=Handshake(0x16) + version(0x0301) + length(2)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01) // TLS 1.0 record version (standard)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	return record
}

// buildClientHelloNoExtensions constructs a ClientHello without any extensions
// section (no extensions length prefix at all).
func buildClientHelloNoExtensions() []byte {
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)             // version
	chBody = append(chBody, make([]byte, 32)...)    // random
	chBody = append(chBody, 0x00)                   // session_id_len
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C) // cipher suites
	chBody = append(chBody, 0x01, 0x00)             // compression
	// No extensions at all

	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	return record
}

func TestExtractSNI(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantSNI  string
		wantErr  error
		checkNil bool // true if we expect nil error specifically
	}{
		{
			name:     "valid ClientHello with SNI",
			data:     buildClientHello("example.com"),
			wantSNI:  "example.com",
			checkNil: true,
		},
		{
			name:     "valid ClientHello without SNI extension",
			data:     buildClientHello(""),
			wantSNI:  "",
			checkNil: true,
		},
		{
			name:     "valid ClientHello no extensions section",
			data:     buildClientHelloNoExtensions(),
			wantSNI:  "",
			checkNil: true,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantSNI: "",
			wantErr: errNotTLS,
		},
		{
			name:    "non-TLS data (HTTP request)",
			data:    []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			wantSNI: "",
			wantErr: errNotTLS,
		},
		{
			name:    "single byte not TLS",
			data:    []byte{0x47}, // 'G' for GET
			wantSNI: "",
			wantErr: errNotTLS,
		},
		{
			name:    "first byte 0x16 but too short for record header",
			data:    []byte{0x16, 0x03, 0x01},
			wantSNI: "",
			wantErr: errTLSMalformed,
		},
		{
			name:    "record header claims more data than available",
			data:    []byte{0x16, 0x03, 0x01, 0x00, 0xFF}, // claims 255 bytes but only header present
			wantSNI: "",
			wantErr: errTLSMalformed,
		},
		{
			name: "handshake type is not ClientHello",
			data: func() []byte {
				d := buildClientHello("example.com")
				d[tlsRecordHeaderLen] = 0x02 // ServerHello instead of ClientHello
				return d
			}(),
			wantSNI: "",
			wantErr: errTLSMalformed,
		},
		{
			name:     "SNI with trailing dot (FQDN)",
			data:     buildClientHello("example.com."),
			wantSNI:  "example.com",
			checkNil: true,
		},
		{
			name:     "SNI with subdomain",
			data:     buildClientHello("api.staging.example.com"),
			wantSNI:  "api.staging.example.com",
			checkNil: true,
		},
		{
			name: "truncated handshake length",
			data: func() []byte {
				d := buildClientHello("example.com")
				// Truncate to just record header + 2 bytes of handshake
				return d[:tlsRecordHeaderLen+2]
			}(),
			wantSNI: "",
			wantErr: errTLSMalformed,
		},
		{
			name: "truncated ClientHello fixed fields",
			data: func() []byte {
				// Record header + handshake header + only 10 bytes (need 34)
				d := []byte{0x16, 0x03, 0x01, 0x00, 0x0E} // record: 14 bytes payload
				d = append(d, 0x01, 0x00, 0x00, 0x0A)     // ClientHello, 10 bytes
				d = append(d, make([]byte, 10)...)        // only 10 bytes, need 34
				return d
			}(),
			wantSNI: "",
			wantErr: errTLSMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sni, err := extractSNI(tt.data)

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("extractSNI() error = %v, want %v", err, tt.wantErr)
				}
			} else if tt.checkNil && err != nil {
				t.Errorf("extractSNI() unexpected error: %v", err)
			}

			if sni != tt.wantSNI {
				t.Errorf("extractSNI() = %q, want %q", sni, tt.wantSNI)
			}
		})
	}
}

func TestExtractSNI_TruncatedSessionID(t *testing.T) {
	// ClientHello with session ID length claiming more bytes than available
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)          // version
	chBody = append(chBody, make([]byte, 32)...) // random
	chBody = append(chBody, 0x20)                // session_id_len = 32
	chBody = append(chBody, make([]byte, 5)...)  // only 5 bytes of session ID

	hsLen := len(chBody)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, hsLen)
	handshake = append(handshake, chBody...)

	recordLen := len(handshake)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, recordLen)
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for truncated session ID, got: %v", err)
	}
}

func TestExtractSNI_TruncatedCipherSuites(t *testing.T) {
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)          // version
	chBody = append(chBody, make([]byte, 32)...) // random
	chBody = append(chBody, 0x00)                // session_id_len = 0
	chBody = append(chBody, 0x00, 0x10)          // cipher_suites_len = 16
	chBody = append(chBody, make([]byte, 4)...)  // only 4 bytes of cipher suites

	hsLen := len(chBody)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, hsLen)
	handshake = append(handshake, chBody...)

	recordLen := len(handshake)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, recordLen)
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for truncated cipher suites, got: %v", err)
	}
}

func TestExtractSNI_TruncatedCompression(t *testing.T) {
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)             // version
	chBody = append(chBody, make([]byte, 32)...)    // random
	chBody = append(chBody, 0x00)                   // session_id_len = 0
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C) // cipher suites
	chBody = append(chBody, 0x05)                   // compression_len = 5
	chBody = append(chBody, 0x00)                   // only 1 byte

	hsLen := len(chBody)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, hsLen)
	handshake = append(handshake, chBody...)

	recordLen := len(handshake)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, recordLen)
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for truncated compression, got: %v", err)
	}
}

func TestExtractSNI_TruncatedExtensionData(t *testing.T) {
	// Extensions length claims more data than available
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)
	chBody = append(chBody, make([]byte, 32)...)
	chBody = append(chBody, 0x00)
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C)
	chBody = append(chBody, 0x01, 0x00)
	// Extensions: length claims 100 bytes
	chBody = append(chBody, 0x00, 0x64)
	// Only 4 bytes of extension data
	chBody = append(chBody, 0x00, 0x00, 0x00, 0x02)

	hsLen := len(chBody)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, hsLen)
	handshake = append(handshake, chBody...)

	recordLen := len(handshake)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, recordLen)
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for truncated extension data, got: %v", err)
	}
}

func TestExtractSNI_SNIExtensionTruncated(t *testing.T) {
	// SNI extension with data length claiming more bytes than available
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)
	chBody = append(chBody, make([]byte, 32)...)
	chBody = append(chBody, 0x00)
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C)
	chBody = append(chBody, 0x01, 0x00)

	// Extensions
	var ext []byte
	// SNI extension type
	ext = append(ext, 0x00, 0x00)
	// Extension data length: 20 bytes
	ext = append(ext, 0x00, 0x14)
	// Server name list length: 18 bytes
	ext = append(ext, 0x00, 0x12)
	// Name type: host_name
	ext = append(ext, 0x00)
	// Name length: 50 bytes (more than available)
	ext = append(ext, 0x00, 0x32)
	// Only 3 bytes of name
	ext = append(ext, 'a', 'b', 'c')

	chBody = appendU16BE(chBody, len(ext))
	chBody = append(chBody, ext...)

	hsLen := len(chBody)
	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, hsLen)
	handshake = append(handshake, chBody...)

	recordLen := len(handshake)
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, recordLen)
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for truncated SNI name, got: %v", err)
	}
}

func TestParseSNIExtension_EmptyList(t *testing.T) {
	// server_name_list with length=0 (no entries)
	data := []byte{0x00, 0x00}
	sni, err := parseSNIExtension(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if sni != "" {
		t.Errorf("expected empty SNI, got %q", sni)
	}
}

func TestParseSNIExtension_TruncatedListLen(t *testing.T) {
	// Only 1 byte, need 2 for list length
	data := []byte{0x00}
	_, err := parseSNIExtension(data)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed, got: %v", err)
	}
}

func TestParseSNIExtension_ListLenExceedsData(t *testing.T) {
	// List length says 100 but only 2 bytes follow
	data := []byte{0x00, 0x64, 0x00, 0x01}
	_, err := parseSNIExtension(data)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed, got: %v", err)
	}
}

func TestParseSNIExtension_NonHostNameType(t *testing.T) {
	// Entry with type 0x01 (not host_name=0x00), should be skipped
	var data []byte
	name := []byte("example.com")
	entryLen := sniEntryHeaderLen + len(name)
	data = appendU16BE(data, entryLen)  // list length
	data = append(data, 0x01)           // name type: NOT host_name
	data = appendU16BE(data, len(name)) // name length
	data = append(data, name...)

	sni, err := parseSNIExtension(data)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if sni != "" {
		t.Errorf("expected empty SNI for non-host_name type, got %q", sni)
	}
}

func TestVerifySNI(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		connectHost  string
		wantCategory string
		wantErr      bool
		wantSNI      string
	}{
		{
			name:         "SNI matches CONNECT target",
			data:         buildClientHello("example.com"),
			connectHost:  "example.com",
			wantCategory: sniCategoryMatch,
			wantErr:      false,
			wantSNI:      "example.com",
		},
		{
			name:         "SNI mismatch",
			data:         buildClientHello("evil.com"),
			connectHost:  "allowed.com",
			wantCategory: sniCategoryMismatch,
			wantErr:      true,
			wantSNI:      "evil.com",
		},
		{
			name:         "case insensitive match",
			data:         buildClientHello("Example.COM"),
			connectHost:  "example.com",
			wantCategory: sniCategoryMatch,
			wantErr:      false,
			wantSNI:      "Example.COM",
		},
		{
			name:         "trailing dot normalization",
			data:         buildClientHello("example.com."),
			connectHost:  "example.com",
			wantCategory: sniCategoryMatch,
			wantErr:      false,
			wantSNI:      "example.com",
		},
		{
			name:         "connect host has trailing dot",
			data:         buildClientHello("example.com"),
			connectHost:  "example.com.",
			wantCategory: sniCategoryMatch,
			wantErr:      false,
			wantSNI:      "example.com",
		},
		{
			name:         "non-TLS data",
			data:         []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"),
			connectHost:  "example.com",
			wantCategory: sniCategoryNotTLS,
			wantErr:      false,
		},
		{
			name:         "valid TLS no SNI extension",
			data:         buildClientHello(""),
			connectHost:  "example.com",
			wantCategory: sniCategoryNoExtension,
			wantErr:      false,
		},
		{
			name:         "no extensions section at all",
			data:         buildClientHelloNoExtensions(),
			connectHost:  "example.com",
			wantCategory: sniCategoryNoExtension,
			wantErr:      false,
		},
		{
			name:         "malformed TLS (0x16 but truncated)",
			data:         []byte{0x16, 0x03, 0x01, 0x00, 0xFF},
			connectHost:  "example.com",
			wantCategory: sniCategoryMalformed,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a pipe for the "client connection" (needed for SetReadDeadline)
			clientConn, serverConn := net.Pipe()
			defer func() { _ = clientConn.Close() }()

			// Write test data and close to signal EOF so Peek returns immediately
			// instead of blocking until the read deadline fires.
			go func() {
				_, _ = serverConn.Write(tt.data)
				_ = serverConn.Close()
			}()

			reader := bufio.NewReaderSize(clientConn, sniPeekSize)

			_, sniHost, category, err := verifySNI(reader, clientConn, tt.connectHost, 2*time.Second)

			if category != tt.wantCategory {
				t.Errorf("category = %q, want %q", category, tt.wantCategory)
			}

			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if tt.wantSNI != "" && sniHost != tt.wantSNI {
				t.Errorf("sniHost = %q, want %q", sniHost, tt.wantSNI)
			}
		})
	}
}

func TestVerifySNI_Timeout(t *testing.T) {
	// Verify timeout returns error (fail-closed). An attacker can delay the
	// ClientHello past the timeout then send a mismatched SNI.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()
	defer func() { _ = serverConn.Close() }()

	// Don't write anything — let it timeout
	reader := bufio.NewReaderSize(clientConn, sniPeekSize)

	start := time.Now()
	_, _, category, err := verifySNI(reader, clientConn, "example.com", 100*time.Millisecond)
	elapsed := time.Since(start)

	if category != sniCategoryTimeout {
		t.Errorf("category = %q, want %q", category, sniCategoryTimeout)
	}
	if err == nil {
		t.Error("expected error on timeout (fail-closed), got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout took %v, expected ~100ms", elapsed)
	}
}

func TestVerifySNI_PreBufferedData(t *testing.T) {
	// Simulate data already buffered in the bufio.Reader (as happens when
	// the HTTP parser reads ahead during CONNECT). Uses a bytes.Reader
	// wrapped in a pipe to pre-fill the bufio buffer before calling verifySNI.
	data := buildClientHello("example.com")

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write(data)
		_ = serverConn.Close()
	}()

	// Production hijack buffers are 4096 bytes, enough for any ClientHello.
	reader := bufio.NewReaderSize(clientConn, 4096)

	_, sniHost, category, err := verifySNI(reader, clientConn, "example.com", 2*time.Second)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if category != sniCategoryMatch {
		t.Errorf("category = %q, want %q", category, sniCategoryMatch)
	}
	if sniHost != "example.com" {
		t.Errorf("sniHost = %q, want %q", sniHost, "example.com")
	}
}

func TestVerifySNI_BytesRemainInBuffer(t *testing.T) {
	// Verify that after verifySNI, the peeked bytes are still available in
	// the bufio.Reader for subsequent reads (relay forwarding).
	data := buildClientHello("example.com")

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write(data)
		_ = serverConn.Close()
	}()

	reader := bufio.NewReaderSize(clientConn, sniPeekSize)

	outReader, _, _, err := verifySNI(reader, clientConn, "example.com", 2*time.Second)
	if err != nil {
		t.Fatalf("verifySNI failed: %v", err)
	}

	// Bytes should still be buffered in the returned reader
	if outReader.Buffered() == 0 {
		t.Error("expected buffered bytes after Peek, got 0")
	}

	// Read the buffered bytes and verify they match the original data
	buf := make([]byte, outReader.Buffered())
	n, readErr := outReader.Read(buf)
	if readErr != nil {
		t.Fatalf("read buffered: %v", readErr)
	}
	if !bytes.Equal(buf[:n], data[:n]) {
		t.Error("buffered bytes do not match original ClientHello data")
	}
}

func TestVerifySNI_DomainFrontingAttack(t *testing.T) {
	// Simulate a domain fronting attack: CONNECT to allowed.com but SNI=evil.com
	data := buildClientHello("evil.com")

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write(data)
		_ = serverConn.Close()
	}()

	reader := bufio.NewReaderSize(clientConn, sniPeekSize)

	_, sniHost, category, err := verifySNI(reader, clientConn, "allowed.com", 2*time.Second)

	if err == nil {
		t.Fatal("expected error for domain fronting attempt, got nil")
	}
	if category != sniCategoryMismatch {
		t.Errorf("category = %q, want %q", category, sniCategoryMismatch)
	}
	if sniHost != "evil.com" {
		t.Errorf("sniHost = %q, want %q", sniHost, "evil.com")
	}
	if !strings.Contains(err.Error(), "SNI mismatch") {
		t.Errorf("error should mention SNI mismatch, got: %v", err)
	}
}

func TestExtractSNI_HandshakeHeaderTooShort(t *testing.T) {
	// Valid record header, payload is only 2 bytes (need 4 for handshake header).
	payload := []byte{0x01, 0x00} // start of ClientHello but too short
	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(payload))
	record = append(record, payload...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for short handshake header, got: %v", err)
	}
}

func TestExtractSNI_HandshakeLenExceedsPayload(t *testing.T) {
	// Handshake header claims 200 bytes but only 10 follow.
	var payload []byte
	payload = append(payload, tlsHandshakeClientHello)
	payload = appendU24BE(payload, 200) // claims 200 bytes
	payload = append(payload, make([]byte, 10)...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(payload))
	record = append(record, payload...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for handshake len exceeding payload, got: %v", err)
	}
}

func TestExtractSNI_NoSessionIDLengthByte(t *testing.T) {
	// ClientHello with exactly 34 fixed bytes and nothing after.
	chBody := make([]byte, tlsClientHelloFixedLen) // version(2) + random(32), no session ID length

	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for missing session ID length, got: %v", err)
	}
}

func TestExtractSNI_NoCipherSuitesLength(t *testing.T) {
	// ClientHello ends right after session ID (no cipher suites length bytes).
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)          // version
	chBody = append(chBody, make([]byte, 32)...) // random
	chBody = append(chBody, 0x00)                // session_id_len = 0
	// No cipher suites length bytes

	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for missing cipher suites length, got: %v", err)
	}
}

func TestExtractSNI_NoCompressionLength(t *testing.T) {
	// ClientHello ends right after cipher suites (no compression length byte).
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)             // version
	chBody = append(chBody, make([]byte, 32)...)    // random
	chBody = append(chBody, 0x00)                   // session_id_len = 0
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C) // cipher suites
	// No compression length byte

	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	_, err := extractSNI(record)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for missing compression length, got: %v", err)
	}
}

func TestExtractSNI_NonSNIExtensionSkipped(t *testing.T) {
	// ClientHello with a non-SNI extension (type 0xFF01) and no SNI extension.
	// Covers the extension skip path (line 150) and no-SNI-found return (line 154).
	var chBody []byte
	chBody = append(chBody, 0x03, 0x03)             // version
	chBody = append(chBody, make([]byte, 32)...)    // random
	chBody = append(chBody, 0x00)                   // session_id_len = 0
	chBody = append(chBody, 0x00, 0x02, 0x00, 0x9C) // cipher suites
	chBody = append(chBody, 0x01, 0x00)             // compression

	// Extension: renegotiation_info (0xFF01), 1 byte data
	ext := []byte{0xFF, 0x01, 0x00, 0x01, 0x00}
	chBody = appendU16BE(chBody, len(ext))
	chBody = append(chBody, ext...)

	var handshake []byte
	handshake = append(handshake, tlsHandshakeClientHello)
	handshake = appendU24BE(handshake, len(chBody))
	handshake = append(handshake, chBody...)

	var record []byte
	record = append(record, tlsRecordTypeHandshake)
	record = append(record, 0x03, 0x01)
	record = appendU16BE(record, len(handshake))
	record = append(record, handshake...)

	sni, err := extractSNI(record)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if sni != "" {
		t.Errorf("expected empty SNI, got %q", sni)
	}
}

func TestParseSNIExtension_NameLenExceedsData(t *testing.T) {
	// SNI entry where name_length claims more bytes than available.
	var data []byte
	entryLen := sniEntryHeaderLen + 3 // header + 3 bytes of name
	data = appendU16BE(data, entryLen)
	data = append(data, sniTypeHostName) // name_type = host_name
	data = appendU16BE(data, 50)         // name_length claims 50 bytes
	data = append(data, 'a', 'b', 'c')   // only 3 bytes

	_, err := parseSNIExtension(data)
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed for name len exceeding data, got: %v", err)
	}
}

func TestVerifySNI_HeaderPeekTooShort(t *testing.T) {
	// Send 0x16 then close immediately. Peek(5) gets < 5 bytes.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write([]byte{0x16, 0x03}) // only 2 bytes after record type
		_ = serverConn.Close()
	}()

	reader := bufio.NewReaderSize(clientConn, sniPeekSize)
	_, _, category, err := verifySNI(reader, clientConn, "example.com", 2*time.Second)

	if category != sniCategoryMalformed {
		t.Errorf("category = %q, want %q", category, sniCategoryMalformed)
	}
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed, got: %v", err)
	}
}

func TestVerifySNI_OversizedRecordClamped(t *testing.T) {
	// Record header claims 20000 bytes (>sniPeekSize). verifySNI clamps to
	// sniPeekSize. Since the record payload is truncated relative to the
	// claimed length, extractSNI returns malformed (fail-closed).
	hello := buildClientHello("example.com")
	// Overwrite record length to claim 20000 bytes
	binary.BigEndian.PutUint16(hello[3:5], 20000)
	// Pad to sniPeekSize so the peek succeeds at the clamped size
	padded := make([]byte, sniPeekSize+tlsRecordHeaderLen)
	copy(padded, hello)

	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write(padded)
		_ = serverConn.Close()
	}()

	reader := bufio.NewReaderSize(clientConn, sniPeekSize)
	_, _, category, err := verifySNI(reader, clientConn, "example.com", 2*time.Second)

	// Oversized record claim with truncated data = fail-closed (malformed)
	if category != sniCategoryMalformed {
		t.Errorf("category = %q, want %q", category, sniCategoryMalformed)
	}
	if !errors.Is(err, errTLSMalformed) {
		t.Errorf("expected errTLSMalformed, got: %v", err)
	}
}

func TestVerifySNI_ReaderResize(t *testing.T) {
	// Build a ClientHello with a long SNI to create a record larger than
	// a small bufio buffer. Verify the reader is transparently resized.
	longHost := strings.Repeat("a", 200) + ".example.com"
	data := buildClientHello(longHost)

	// Use a tiny buffer (64 bytes) that's smaller than the TLS record.
	// verifySNI must resize the reader to peek the full record.
	clientConn, serverConn := net.Pipe()
	defer func() { _ = clientConn.Close() }()

	go func() {
		_, _ = serverConn.Write(data)
		_ = serverConn.Close()
	}()

	smallBuf := bufio.NewReaderSize(clientConn, 64) // 64 bytes, much smaller than record
	resized, sniHost, category, err := verifySNI(smallBuf, clientConn, longHost, 2*time.Second)
	if err != nil {
		t.Fatalf("verifySNI failed: %v", err)
	}
	if category != sniCategoryMatch {
		t.Errorf("category = %q, want %q", category, sniCategoryMatch)
	}
	if sniHost != longHost {
		t.Errorf("sniHost = %q, want %q", sniHost, longHost)
	}
	// The returned reader should have been resized (larger than original 64)
	if resized.Size() <= 64 {
		t.Errorf("expected resized reader (>64), got size %d", resized.Size())
	}
}
