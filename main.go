package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Frame types as defined in RFC 7540 Section 6
const (
	FrameTypeDATA          = 0x0
	FrameTypeHEADERS       = 0x1
	FrameTypePRIORITY      = 0x2
	FrameTypeRST_STREAM    = 0x3
	FrameTypeSETTINGS      = 0x4
	FrameTypePUSH_PROMISE  = 0x5
	FrameTypePING          = 0x6
	FrameTypeGOAWAY        = 0x7
	FrameTypeWINDOW_UPDATE = 0x8
	FrameTypeCONTINUATION  = 0x9
)

// Flags for different frame types
const (
	FlagDataEndStream     = 0x1
	FlagDataPadded        = 0x8
	FlagHeadersEndStream  = 0x1
	FlagHeadersEndHeaders = 0x4
	FlagHeadersPadded     = 0x8
	FlagHeadersPriority   = 0x20
	FlagSettingsAck       = 0x1
	FlagPingAck           = 0x1
)

// Settings parameters as defined in RFC 7540 Section 6.5.2
const (
	SettingsHeaderTableSize      = 0x1
	SettingsEnablePush           = 0x2
	SettingsMaxConcurrentStreams = 0x3
	SettingsInitialWindowSize    = 0x4
	SettingsMaxFrameSize         = 0x5
	SettingsMaxHeaderListSize    = 0x6
)

// Error codes as defined in RFC 7540 Section 7
const (
	ErrorCodeNoError            = 0x0
	ErrorCodeProtocolError      = 0x1
	ErrorCodeInternalError      = 0x2
	ErrorCodeFlowControlError   = 0x3
	ErrorCodeSettingsTimeout    = 0x4
	ErrorCodeStreamClosed       = 0x5
	ErrorCodeFrameSizeError     = 0x6
	ErrorCodeRefusedStream      = 0x7
	ErrorCodeCancel             = 0x8
	ErrorCodeCompressionError   = 0x9
	ErrorCodeConnectError       = 0xa
	ErrorCodeEnhanceYourCalm    = 0xb
	ErrorCodeInadequateSecurity = 0xc
	ErrorCodeHTTP11Required     = 0xd
)

// Connection preface as defined in RFC 7540 Section 3.5
var ConnectionPreface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// Frame represents an HTTP/2 frame as defined in RFC 7540 Section 4.1
type Frame struct {
	Length   uint32 // 24-bit length
	Type     uint8  // 8-bit type
	Flags    uint8  // 8-bit flags
	StreamID uint32 // 31-bit stream identifier
	Payload  []byte // Variable length payload
}

// Setting represents a single HTTP/2 setting parameter
type Setting struct {
	ID    uint16
	Value uint32
}

// Connection represents an HTTP/2 connection
type Connection struct {
	conn           net.Conn
	reader         *bufio.Reader
	writer         *bufio.Writer
	isServer       bool
	settings       map[uint16]uint32
	peerSettings   map[uint16]uint32
	streamsMutex   sync.RWMutex
	streams        map[uint32]*Stream
	lastStreamID   uint32
	windowSize     uint32
	peerWindowSize uint32
	headerEncoder  *HPACKEncoder
	headerDecoder  *HPACKDecoder
}

// Stream represents an HTTP/2 stream
type Stream struct {
	ID         uint32
	State      StreamState
	WindowSize uint32
	PeerWindow uint32
	Headers    map[string]string
	Data       []byte
	EndStream  bool
}

// StreamState represents the state of an HTTP/2 stream as defined in RFC 7540 Section 5.1
type StreamState int

const (
	StreamStateIdle StreamState = iota
	StreamStateReservedLocal
	StreamStateReservedRemote
	StreamStateOpen
	StreamStateHalfClosedLocal
	StreamStateHalfClosedRemote
	StreamStateClosed
)

// NewClient creates a new HTTP/2 client connection
func NewClient(address string, useTLS bool) (*Connection, error) {
	var conn net.Conn
	var err error

	if useTLS {
		config := &tls.Config{
			NextProtos: []string{"h2"},
		}
		conn, err = tls.Dial("tcp", address, config)
		if err != nil {
			return nil, fmt.Errorf("failed to establish TLS connection: %w", err)
		}
	} else {
		conn, err = net.Dial("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("failed to establish TCP connection: %w", err)
		}
	}

	c := &Connection{
		conn:           conn,
		reader:         bufio.NewReader(conn),
		writer:         bufio.NewWriter(conn),
		isServer:       false,
		settings:       make(map[uint16]uint32),
		peerSettings:   make(map[uint16]uint32),
		streams:        make(map[uint32]*Stream),
		windowSize:     65535, // Initial window size per RFC 7540
		peerWindowSize: 65535,
		headerEncoder:  NewHPACKEncoder(),
		headerDecoder:  NewHPACKDecoder(),
	}

	// Set default settings as per RFC 7540 Section 6.5.2
	c.settings[SettingsHeaderTableSize] = 4096
	c.settings[SettingsEnablePush] = 1
	c.settings[SettingsInitialWindowSize] = 65535
	c.settings[SettingsMaxFrameSize] = 16384

	if err := c.sendConnectionPreface(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send connection preface: %w", err)
	}

	return c, nil
}

// sendConnectionPreface sends the client connection preface as per RFC 7540 Section 3.5
func (c *Connection) sendConnectionPreface() error {
	// Send the connection preface magic string
	if _, err := c.conn.Write(ConnectionPreface); err != nil {
		return err
	}

	// Send initial SETTINGS frame
	settingsFrame := c.createSettingsFrame(false)
	return c.writeFrame(settingsFrame)
}

// createSettingsFrame creates a SETTINGS frame with current settings
func (c *Connection) createSettingsFrame(ack bool) *Frame {
	frame := &Frame{
		Type:     FrameTypeSETTINGS,
		StreamID: 0,
	}

	if ack {
		frame.Flags = FlagSettingsAck
		frame.Length = 0
		frame.Payload = []byte{}
		return frame
	}

	// Build settings payload
	var payload bytes.Buffer
	for id, value := range c.settings {
		binary.Write(&payload, binary.BigEndian, id)
		binary.Write(&payload, binary.BigEndian, value)
	}

	frame.Payload = payload.Bytes()
	frame.Length = uint32(len(frame.Payload))
	return frame
}

// writeFrame writes a frame to the connection
func (c *Connection) writeFrame(frame *Frame) error {
	header := make([]byte, 9)

	// Length (24 bits)
	header[0] = byte(frame.Length >> 16)
	header[1] = byte(frame.Length >> 8)
	header[2] = byte(frame.Length)

	// Type (8 bits)
	header[3] = frame.Type

	// Flags (8 bits)
	header[4] = frame.Flags

	// Stream ID (31 bits, R bit must be 0)
	binary.BigEndian.PutUint32(header[5:9], frame.StreamID&0x7FFFFFFF)

	if _, err := c.writer.Write(header); err != nil {
		return err
	}

	if len(frame.Payload) > 0 {
		if _, err := c.writer.Write(frame.Payload); err != nil {
			return err
		}
	}

	return c.writer.Flush()
}

// readFrame reads a frame from the connection
func (c *Connection) readFrame() (*Frame, error) {
	header := make([]byte, 9)
	if _, err := io.ReadFull(c.reader, header); err != nil {
		return nil, err
	}

	frame := &Frame{
		Length:   uint32(header[0])<<16 | uint32(header[1])<<8 | uint32(header[2]),
		Type:     header[3],
		Flags:    header[4],
		StreamID: binary.BigEndian.Uint32(header[5:9]) & 0x7FFFFFFF,
	}

	if frame.Length > 0 {
		frame.Payload = make([]byte, frame.Length)
		if _, err := io.ReadFull(c.reader, frame.Payload); err != nil {
			return nil, err
		}
	}

	return frame, nil
}

// processFrame processes an incoming frame according to its type
func (c *Connection) processFrame(frame *Frame) error {
	switch frame.Type {
	case FrameTypeSETTINGS:
		return c.handleSettingsFrame(frame)
	case FrameTypePING:
		return c.handlePingFrame(frame)
	case FrameTypeWINDOW_UPDATE:
		return c.handleWindowUpdateFrame(frame)
	case FrameTypeGOAWAY:
		return c.handleGoAwayFrame(frame)
	case FrameTypeHEADERS:
		return c.handleHeadersFrame(frame)
	case FrameTypeDATA:
		return c.handleDataFrame(frame)
	default:
		// Ignore unknown frame types as per RFC 7540 Section 4.1
		return nil
	}
}

// handleSettingsFrame processes SETTINGS frames as per RFC 7540 Section 6.5
func (c *Connection) handleSettingsFrame(frame *Frame) error {
	if frame.StreamID != 0 {
		return fmt.Errorf("SETTINGS frame with non-zero stream ID")
	}

	if frame.Flags&FlagSettingsAck != 0 {
		// ACK frame, no processing needed
		return nil
	}

	if len(frame.Payload)%6 != 0 {
		return fmt.Errorf("invalid SETTINGS frame payload length")
	}

	// Process settings
	for i := 0; i < len(frame.Payload); i += 6 {
		id := binary.BigEndian.Uint16(frame.Payload[i : i+2])
		value := binary.BigEndian.Uint32(frame.Payload[i+2 : i+6])
		c.peerSettings[id] = value
	}

	// Send ACK
	ackFrame := c.createSettingsFrame(true)
	return c.writeFrame(ackFrame)
}

// handlePingFrame processes PING frames as per RFC 7540 Section 6.7
func (c *Connection) handlePingFrame(frame *Frame) error {
	if frame.StreamID != 0 {
		return fmt.Errorf("PING frame with non-zero stream ID")
	}

	if len(frame.Payload) != 8 {
		return fmt.Errorf("invalid PING frame payload length")
	}

	if frame.Flags&FlagPingAck == 0 {
		// Send PING ACK
		ackFrame := &Frame{
			Length:   8,
			Type:     FrameTypePING,
			Flags:    FlagPingAck,
			StreamID: 0,
			Payload:  frame.Payload,
		}
		return c.writeFrame(ackFrame)
	}

	return nil
}

// handleWindowUpdateFrame processes WINDOW_UPDATE frames as per RFC 7540 Section 6.9
func (c *Connection) handleWindowUpdateFrame(frame *Frame) error {
	if len(frame.Payload) != 4 {
		return fmt.Errorf("invalid WINDOW_UPDATE frame payload length")
	}

	increment := binary.BigEndian.Uint32(frame.Payload) & 0x7FFFFFFF
	if increment == 0 {
		return fmt.Errorf("WINDOW_UPDATE with zero increment")
	}

	if frame.StreamID == 0 {
		c.peerWindowSize += increment
	} else {
		// Update stream window
		c.streamsMutex.Lock()
		if stream, exists := c.streams[frame.StreamID]; exists {
			stream.PeerWindow += increment
		}
		c.streamsMutex.Unlock()
	}

	return nil
}

// handleGoAwayFrame processes GOAWAY frames as per RFC 7540 Section 6.8
func (c *Connection) handleGoAwayFrame(frame *Frame) error {
	if frame.StreamID != 0 {
		return fmt.Errorf("GOAWAY frame with non-zero stream ID")
	}

	if len(frame.Payload) < 8 {
		return fmt.Errorf("invalid GOAWAY frame payload length")
	}

	lastStreamID := binary.BigEndian.Uint32(frame.Payload[0:4]) & 0x7FFFFFFF
	errorCode := binary.BigEndian.Uint32(frame.Payload[4:8])

	fmt.Printf("Received GOAWAY: last stream ID %d, error code %d\n", lastStreamID, errorCode)
	return fmt.Errorf("connection terminated by peer")
}

// handleHeadersFrame processes HEADERS frames as per RFC 7540 Section 6.2
func (c *Connection) handleHeadersFrame(frame *Frame) error {
	// This is a simplified implementation
	// In a full implementation, you would need HPACK decompression
	c.streamsMutex.Lock()
	defer c.streamsMutex.Unlock()

	stream, exists := c.streams[frame.StreamID]
	if !exists {
		stream = &Stream{
			ID:         frame.StreamID,
			State:      StreamStateOpen,
			WindowSize: 65535,
			PeerWindow: 65535,
			Headers:    make(map[string]string),
		}
		c.streams[frame.StreamID] = stream
	}

	if frame.Flags&FlagHeadersEndStream != 0 {
		stream.EndStream = true
		if stream.State == StreamStateOpen {
			stream.State = StreamStateHalfClosedRemote
		}
	}

	return nil
}

// handleDataFrame processes DATA frames as per RFC 7540 Section 6.1
func (c *Connection) handleDataFrame(frame *Frame) error {
	if frame.StreamID == 0 {
		return fmt.Errorf("DATA frame with zero stream ID")
	}

	c.streamsMutex.Lock()
	defer c.streamsMutex.Unlock()

	stream, exists := c.streams[frame.StreamID]
	if !exists {
		return fmt.Errorf("DATA frame for non-existent stream")
	}

	stream.Data = append(stream.Data, frame.Payload...)

	if frame.Flags&FlagDataEndStream != 0 {
		stream.EndStream = true
		if stream.State == StreamStateOpen {
			stream.State = StreamStateHalfClosedRemote
		}
	}

	return nil
}

// Close closes the HTTP/2 connection
func (c *Connection) Close() error {
	return c.conn.Close()
}

// StartReading begins reading frames from the connection
func (c *Connection) StartReading() error {
	for {
		frame, err := c.readFrame()
		if err != nil {
			return err
		}

		if err := c.processFrame(frame); err != nil {
			return err
		}
	}
}

// Placeholder HPACK implementation
type HPACKEncoder struct{}
type HPACKDecoder struct{}

func NewHPACKEncoder() *HPACKEncoder {
	return &HPACKEncoder{}
}

func NewHPACKDecoder() *HPACKDecoder {
	return &HPACKDecoder{}
}

// Request represents an HTTP/2 request
type Request struct {
	Method    string
	Path      string
	Authority string
	Scheme    string
	Headers   map[string]string
	Body      []byte
}

// Response represents an HTTP/2 response
type Response struct {
	Status  string
	Headers map[string]string
	Body    []byte
}

// SendRequest sends an HTTP/2 request and returns the response
func (c *Connection) SendRequest(req *Request) (*Response, error) {
	streamID := c.getNextStreamID()

	// Create and send HEADERS frame with pseudo-headers
	headersFrame, err := c.createHeadersFrame(streamID, req)
	if err != nil {
		return nil, fmt.Errorf("failed to create headers frame: %w", err)
	}

	if err := c.writeFrame(headersFrame); err != nil {
		return nil, fmt.Errorf("failed to send headers frame: %w", err)
	}

	// Send DATA frame if request has a body
	if len(req.Body) > 0 {
		dataFrame := c.createDataFrame(streamID, req.Body, true)
		if err := c.writeFrame(dataFrame); err != nil {
			return nil, fmt.Errorf("failed to send data frame: %w", err)
		}
	}

	// Wait for response
	return c.waitForResponse(streamID)
}

// getNextStreamID returns the next available stream ID for client-initiated streams
func (c *Connection) getNextStreamID() uint32 {
	c.streamsMutex.Lock()
	defer c.streamsMutex.Unlock()

	// Client-initiated streams must be odd numbers per RFC 7540 Section 5.1.1
	if c.lastStreamID == 0 {
		c.lastStreamID = 1
	} else {
		c.lastStreamID += 2
	}
	return c.lastStreamID
}

// createHeadersFrame creates a HEADERS frame for the request
func (c *Connection) createHeadersFrame(streamID uint32, req *Request) (*Frame, error) {
	// Build pseudo-headers as required by RFC 7540 Section 8.1.2.3
	headers := map[string]string{
		":method":    req.Method,
		":path":      req.Path,
		":scheme":    req.Scheme,
		":authority": req.Authority,
	}

	// Add regular headers
	for key, value := range req.Headers {
		headers[key] = value
	}

	// In a complete implementation, this would use HPACK encoding
	// For now, we use a simplified header encoding
	payload, err := c.encodeHeaders(headers)
	if err != nil {
		return nil, err
	}

	flags := FlagHeadersEndHeaders
	if len(req.Body) == 0 {
		flags |= FlagHeadersEndStream
	}

	frame := &Frame{
		Length:   uint32(len(payload)),
		Type:     FrameTypeHEADERS,
		Flags:    uint8(flags),
		StreamID: streamID,
		Payload:  payload,
	}

	// Create stream entry
	c.streamsMutex.Lock()
	c.streams[streamID] = &Stream{
		ID:         streamID,
		State:      StreamStateOpen,
		WindowSize: 65535,
		PeerWindow: 65535,
		Headers:    make(map[string]string),
	}
	c.streamsMutex.Unlock()

	return frame, nil
}

// createDataFrame creates a DATA frame for request body
func (c *Connection) createDataFrame(streamID uint32, data []byte, endStream bool) *Frame {
	flags := uint8(0)
	if endStream {
		flags |= FlagDataEndStream
	}

	return &Frame{
		Length:   uint32(len(data)),
		Type:     FrameTypeDATA,
		Flags:    flags,
		StreamID: streamID,
		Payload:  data,
	}
}

// encodeHeaders provides simplified header encoding
// In a complete implementation, this would use HPACK compression
func (c *Connection) encodeHeaders(headers map[string]string) ([]byte, error) {
	var buf bytes.Buffer

	// Simplified encoding: length-prefixed strings
	for name, value := range headers {
		// Write name length and name
		nameBytes := []byte(name)
		binary.Write(&buf, binary.BigEndian, uint16(len(nameBytes)))
		buf.Write(nameBytes)

		// Write value length and value
		valueBytes := []byte(value)
		binary.Write(&buf, binary.BigEndian, uint16(len(valueBytes)))
		buf.Write(valueBytes)
	}

	return buf.Bytes(), nil
}

// decodeHeaders provides simplified header decoding
func (c *Connection) decodeHeaders(payload []byte) (map[string]string, error) {
	headers := make(map[string]string)
	buf := bytes.NewReader(payload)

	for buf.Len() > 0 {
		// Read name length
		var nameLen uint16
		if err := binary.Read(buf, binary.BigEndian, &nameLen); err != nil {
			return nil, err
		}

		// Read name
		nameBytes := make([]byte, nameLen)
		if _, err := buf.Read(nameBytes); err != nil {
			return nil, err
		}

		// Read value length
		var valueLen uint16
		if err := binary.Read(buf, binary.BigEndian, &valueLen); err != nil {
			return nil, err
		}

		// Read value
		valueBytes := make([]byte, valueLen)
		if _, err := buf.Read(valueBytes); err != nil {
			return nil, err
		}

		headers[string(nameBytes)] = string(valueBytes)
	}

	return headers, nil
}

// waitForResponse waits for a complete response on the specified stream
func (c *Connection) waitForResponse(streamID uint32) (*Response, error) {
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return nil, fmt.Errorf("request timeout")
		case <-ticker.C:
			c.streamsMutex.RLock()
			stream, exists := c.streams[streamID]
			c.streamsMutex.RUnlock()

			if !exists {
				continue
			}

			if stream.EndStream && len(stream.Headers) > 0 {
				response := &Response{
					Headers: stream.Headers,
					Body:    stream.Data,
				}

				// Extract status from headers
				if status, ok := stream.Headers[":status"]; ok {
					response.Status = status
				}

				// Clean up stream
				c.streamsMutex.Lock()
				delete(c.streams, streamID)
				c.streamsMutex.Unlock()

				return response, nil
			}
		}
	}
}

// Enhanced handleHeadersFrame with header decoding
func (c *Connection) handleHeadersFrameEnhanced(frame *Frame) error {
	c.streamsMutex.Lock()
	defer c.streamsMutex.Unlock()

	stream, exists := c.streams[frame.StreamID]
	if !exists {
		stream = &Stream{
			ID:         frame.StreamID,
			State:      StreamStateOpen,
			WindowSize: 65535,
			PeerWindow: 65535,
			Headers:    make(map[string]string),
		}
		c.streams[frame.StreamID] = stream
	}

	// Decode headers from payload
	headers, err := c.decodeHeaders(frame.Payload)
	if err != nil {
		return fmt.Errorf("failed to decode headers: %w", err)
	}

	// Merge headers
	for key, value := range headers {
		stream.Headers[key] = value
	}

	if frame.Flags&FlagHeadersEndStream != 0 {
		stream.EndStream = true
		if stream.State == StreamStateOpen {
			stream.State = StreamStateHalfClosedRemote
		}
	}

	return nil
}

// GET sends a GET request
func (c *Connection) GET(url, authority string) (*Response, error) {
	req := &Request{
		Method:    "GET",
		Path:      url,
		Authority: authority,
		Scheme:    "https",
		Headers:   make(map[string]string),
	}

	return c.SendRequest(req)
}

// POST sends a POST request with body
func (c *Connection) POST(url, authority string, body []byte, contentType string) (*Response, error) {
	req := &Request{
		Method:    "POST",
		Path:      url,
		Authority: authority,
		Scheme:    "https",
		Headers: map[string]string{
			"content-type": contentType,
		},
		Body: body,
	}

	return c.SendRequest(req)
}

// Replace handleHeadersFrame with enhanced version
func (c *Connection) processFrameEnhanced(frame *Frame) error {
	switch frame.Type {
	case FrameTypeSETTINGS:
		return c.handleSettingsFrame(frame)
	case FrameTypePING:
		return c.handlePingFrame(frame)
	case FrameTypeWINDOW_UPDATE:
		return c.handleWindowUpdateFrame(frame)
	case FrameTypeGOAWAY:
		return c.handleGoAwayFrame(frame)
	case FrameTypeHEADERS:
		return c.handleHeadersFrameEnhanced(frame)
	case FrameTypeDATA:
		return c.handleDataFrame(frame)
	default:
		return nil
	}
}

// Enhanced StartReading with improved frame processing
func (c *Connection) StartReadingEnhanced() error {
	for {
		frame, err := c.readFrame()
		if err != nil {
			return err
		}

		if err := c.processFrameEnhanced(frame); err != nil {
			return err
		}
	}
}

// Example usage demonstrating HTTP/2 requests
func ExampleHTTP2Requests() error {
	// Create a client connection
	conn, err := NewClient("httpbin.org:443", true)
	if err != nil {
		return fmt.Errorf("failed to create connection: %w", err)
	}
	defer conn.Close()

	// Start reading frames in a goroutine
	go func() {
		if err := conn.StartReadingEnhanced(); err != nil {
			fmt.Printf("Error reading frames: %v\n", err)
		}
	}()

	// Allow time for connection establishment
	time.Sleep(200 * time.Millisecond)

	// Send a GET request
	response, err := conn.GET("/get", "httpbin.org")
	if err != nil {
		return fmt.Errorf("GET request failed: %w", err)
	}

	fmt.Printf("GET Response Status: %s\n", response.Status)
	fmt.Printf("Response Body Length: %d bytes\n", len(response.Body))

	// Send a POST request
	postData := []byte(`{"message": "Hello HTTP/2"}`)
	postResponse, err := conn.POST("/post", "httpbin.org", postData, "application/json")
	if err != nil {
		return fmt.Errorf("POST request failed: %w", err)
	}

	fmt.Printf("POST Response Status: %s\n", postResponse.Status)
	fmt.Printf("POST Response Body Length: %d bytes\n", len(postResponse.Body))

	return nil
}

func main() {
	// Create a client connection
	conn, err := NewClient("localhost:1234", false)
	if err != nil {
		panic(fmt.Sprintf("failed to create connection: %v", err))
	}
	defer conn.Close()

	// Start reading frames in a goroutine
	go func() {
		if err := conn.StartReadingEnhanced(); err != nil {
			fmt.Printf("Error reading frames: %v\n", err)
		}
	}()

	// Allow time for connection establishment
	time.Sleep(200 * time.Millisecond)

	// Send a GET request
	response, err := conn.GET("/info", "httpbin.org")
	if err != nil {
		panic(fmt.Sprintf("GET request failed: %v", err))
	}

	fmt.Printf("GET Response Status: %s\n", response.Status)
	fmt.Printf("Response Body Length: %d bytes\n", len(response.Body))
}
