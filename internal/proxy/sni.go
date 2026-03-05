package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// SNI extraction errors (exported for testing).
var (
	errNotTLS       = errors.New("not a TLS record")
	errTLSMalformed = errors.New("malformed TLS ClientHello")
)

// SNI verification result categories.
const (
	sniCategoryMatch       = "match"
	sniCategoryMismatch    = "mismatch"
	sniCategoryNotTLS      = "not_tls"
	sniCategoryNoExtension = "no_extension"
	sniCategoryMalformed   = "malformed_tls"
	sniCategoryTimeout     = "timeout"
)

// TLS record and handshake constants.
const (
	tlsRecordTypeHandshake  = 0x16
	tlsHandshakeClientHello = 0x01
	tlsExtensionSNI         = 0x0000
	sniTypeHostName         = 0x00
	sniPeekSize             = 16384 // 16KB: enough for any ClientHello
	sniReadTimeoutDefault   = 5 * time.Second
	tlsRecordHeaderLen      = 5  // type(1) + version(2) + length(2)
	tlsHandshakeHeaderLen   = 4  // type(1) + length(3)
	tlsClientHelloFixedLen  = 34 // version(2) + random(32)
	tlsExtensionHeaderLen   = 4  // type(2) + length(2)
	sniListHeaderLen        = 2  // server_name_list length(2)
	sniEntryHeaderLen       = 3  // name_type(1) + name_length(2)
)

// extractSNI parses a TLS ClientHello and returns the SNI hostname.
// Returns ("", errNotTLS) if data does not start with a TLS handshake record.
// Returns ("", nil) if valid ClientHello but no SNI extension present.
// Returns ("", errTLSMalformed) if data starts with 0x16 but fails to parse.
// Returns (hostname, nil) on successful extraction.
func extractSNI(data []byte) (string, error) {
	if len(data) == 0 {
		return "", errNotTLS
	}

	// Record layer: type must be handshake (0x16)
	if data[0] != tlsRecordTypeHandshake {
		return "", errNotTLS
	}

	if len(data) < tlsRecordHeaderLen {
		return "", errTLSMalformed
	}

	// Record length (bytes 3-4). We don't need the version (bytes 1-2).
	recordLen := int(data[3])<<8 | int(data[4])
	payload := data[tlsRecordHeaderLen:]
	if len(payload) < recordLen {
		// Truncated record: data claims to be TLS but is incomplete.
		return "", errTLSMalformed
	}
	payload = payload[:recordLen]

	// Handshake header: type must be ClientHello (0x01)
	if len(payload) < tlsHandshakeHeaderLen {
		return "", errTLSMalformed
	}
	if payload[0] != tlsHandshakeClientHello {
		return "", errTLSMalformed
	}
	// Handshake length (3 bytes)
	hsLen := int(payload[1])<<16 | int(payload[2])<<8 | int(payload[3])
	payload = payload[tlsHandshakeHeaderLen:]
	if len(payload) < hsLen {
		return "", errTLSMalformed
	}
	payload = payload[:hsLen]

	// ClientHello fixed fields: version(2) + random(32) = 34 bytes
	if len(payload) < tlsClientHelloFixedLen {
		return "", errTLSMalformed
	}
	payload = payload[tlsClientHelloFixedLen:]

	// Session ID (variable length, 1-byte length prefix)
	if len(payload) < 1 {
		return "", errTLSMalformed
	}
	sidLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < sidLen {
		return "", errTLSMalformed
	}
	payload = payload[sidLen:]

	// Cipher suites (variable length, 2-byte length prefix)
	if len(payload) < 2 {
		return "", errTLSMalformed
	}
	csLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < csLen {
		return "", errTLSMalformed
	}
	payload = payload[csLen:]

	// Compression methods (variable length, 1-byte length prefix)
	if len(payload) < 1 {
		return "", errTLSMalformed
	}
	compLen := int(payload[0])
	payload = payload[1:]
	if len(payload) < compLen {
		return "", errTLSMalformed
	}
	payload = payload[compLen:]

	// Extensions (2-byte length prefix). No extensions = no SNI.
	if len(payload) < 2 {
		return "", nil
	}
	extLen := int(payload[0])<<8 | int(payload[1])
	payload = payload[2:]
	if len(payload) < extLen {
		return "", errTLSMalformed
	}
	payload = payload[:extLen]

	// Iterate extensions looking for SNI (type 0x0000)
	for len(payload) >= tlsExtensionHeaderLen {
		extType := int(payload[0])<<8 | int(payload[1])
		extDataLen := int(payload[2])<<8 | int(payload[3])
		payload = payload[tlsExtensionHeaderLen:]
		if len(payload) < extDataLen {
			return "", errTLSMalformed
		}

		if extType == tlsExtensionSNI {
			return parseSNIExtension(payload[:extDataLen])
		}

		payload = payload[extDataLen:]
	}

	// Valid ClientHello, no SNI extension found.
	return "", nil
}

// parseSNIExtension extracts the hostname from an SNI extension payload.
func parseSNIExtension(data []byte) (string, error) {
	// server_name_list: 2-byte length prefix
	if len(data) < sniListHeaderLen {
		return "", errTLSMalformed
	}
	listLen := int(data[0])<<8 | int(data[1])
	data = data[sniListHeaderLen:]
	if len(data) < listLen {
		return "", errTLSMalformed
	}
	data = data[:listLen]

	// Iterate server_name entries
	for len(data) >= sniEntryHeaderLen {
		nameType := data[0]
		nameLen := int(data[1])<<8 | int(data[2])
		data = data[sniEntryHeaderLen:]
		if len(data) < nameLen {
			return "", errTLSMalformed
		}

		if nameType == sniTypeHostName {
			hostname := string(data[:nameLen])
			// Strip trailing dot (FQDN normalization)
			hostname = strings.TrimSuffix(hostname, ".")
			return hostname, nil
		}

		data = data[nameLen:]
	}

	// SNI extension present but no host_name entry.
	return "", nil
}

// verifySNI reads the first bytes from the client connection, parses any
// TLS ClientHello, and verifies the SNI matches the CONNECT target.
//
// Returns the verification category and an error. A nil error means the
// connection should proceed. A non-nil error means the connection should
// be closed (mismatch, malformed, or timeout).
//
// Uses bufio.Reader.Peek() so bytes remain buffered for the relay. If the
// TLS record is larger than the reader's buffer, a new reader with a larger
// buffer is returned. The caller must use the returned reader for subsequent
// reads (it wraps the original, preserving already-buffered data).
func verifySNI(reader *bufio.Reader, clientConn net.Conn, connectHost string, timeout time.Duration) (outReader *bufio.Reader, sniHost, category string, err error) {
	outReader = reader

	// Set read deadline so Peek doesn't block forever.
	_ = clientConn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = clientConn.SetReadDeadline(time.Time{}) }()

	// Step 1: Peek first byte to check if this is TLS. Peek(1) blocks until
	// at least 1 byte arrives or the read deadline fires.
	first, peekErr := outReader.Peek(1)
	if len(first) == 0 {
		// No data before timeout: fail-closed. An attacker can delay the
		// ClientHello past the timeout then send a mismatched SNI.
		if peekErr != nil {
			return outReader, "", sniCategoryTimeout, fmt.Errorf("SNI verification timeout: no data received within %v", timeout)
		}
		return outReader, "", sniCategoryTimeout, fmt.Errorf("SNI verification timeout: empty peek")
	}

	if first[0] != tlsRecordTypeHandshake {
		return outReader, "", sniCategoryNotTLS, nil
	}

	// Step 2: Peek record header (5 bytes) to learn the record length.
	header, _ := outReader.Peek(tlsRecordHeaderLen)
	if len(header) < tlsRecordHeaderLen {
		return outReader, "", sniCategoryMalformed, errTLSMalformed
	}

	// Step 3: Peek the full TLS record. Resize the reader if needed so
	// large ClientHello records (>4KB with many extensions) are not
	// truncated and misclassified as malformed.
	recordLen := (int(header[3])<<8 | int(header[4])) + tlsRecordHeaderLen
	if recordLen > sniPeekSize {
		recordLen = sniPeekSize
	}
	if recordLen > outReader.Size() {
		// bufio.NewReaderSize wrapping an existing bufio.Reader preserves
		// already-buffered bytes (they're read from the old reader first).
		outReader = bufio.NewReaderSize(outReader, recordLen)
	}
	peeked, _ := outReader.Peek(recordLen)

	hostname, extractErr := extractSNI(peeked)

	if errors.Is(extractErr, errTLSMalformed) {
		return outReader, "", sniCategoryMalformed, extractErr
	}

	if errors.Is(extractErr, errNotTLS) {
		// Should not happen since we checked first[0] == 0x16, but be safe.
		return outReader, "", sniCategoryNotTLS, nil
	}

	// Valid TLS but no SNI extension
	if hostname == "" && extractErr == nil {
		return outReader, "", sniCategoryNoExtension, nil
	}

	// Compare SNI hostname to CONNECT target (case-insensitive, strip trailing dot)
	normalizedConnect := strings.TrimSuffix(strings.ToLower(connectHost), ".")
	normalizedSNI := strings.TrimSuffix(strings.ToLower(hostname), ".")

	if normalizedSNI != normalizedConnect {
		return outReader, hostname, sniCategoryMismatch, fmt.Errorf(
			"SNI mismatch: CONNECT target %q but ClientHello SNI %q",
			connectHost, hostname,
		)
	}

	return outReader, hostname, sniCategoryMatch, nil
}
