package main

import (
	"bytes"
	"fmt"
	"io"
)

// HeaderField represents a name-value pair as defined in RFC 7541 Section 1.3
type HeaderField struct {
	Name  string
	Value string
}

// Static table as defined in RFC 7541 Appendix A
// Index 0 is not used, actual table starts from index 1
var staticTable = []HeaderField{
	{"", ""},                             // Index 0 - not used
	{":authority", ""},                   // 1
	{":method", "GET"},                   // 2
	{":method", "POST"},                  // 3
	{":path", "/"},                       // 4
	{":path", "/index.html"},             // 5
	{":scheme", "http"},                  // 6
	{":scheme", "https"},                 // 7
	{":status", "200"},                   // 8
	{":status", "204"},                   // 9
	{":status", "206"},                   // 10
	{":status", "304"},                   // 11
	{":status", "400"},                   // 12
	{":status", "404"},                   // 13
	{":status", "500"},                   // 14
	{"accept-charset", ""},               // 15
	{"accept-encoding", "gzip, deflate"}, // 16
	{"accept-language", ""},              // 17
	{"accept-ranges", ""},                // 18
	{"accept", ""},                       // 19
	{"access-control-allow-origin", ""},  // 20
	{"age", ""},                          // 21
	{"allow", ""},                        // 22
	{"authorization", ""},                // 23
	{"cache-control", ""},                // 24
	{"content-disposition", ""},          // 25
	{"content-encoding", ""},             // 26
	{"content-language", ""},             // 27
	{"content-length", ""},               // 28
	{"content-location", ""},             // 29
	{"content-range", ""},                // 30
	{"content-type", ""},                 // 31
	{"cookie", ""},                       // 32
	{"date", ""},                         // 33
	{"etag", ""},                         // 34
	{"expect", ""},                       // 35
	{"expires", ""},                      // 36
	{"from", ""},                         // 37
	{"host", ""},                         // 38
	{"if-match", ""},                     // 39
	{"if-modified-since", ""},            // 40
	{"if-none-match", ""},                // 41
	{"if-range", ""},                     // 42
	{"if-unmodified-since", ""},          // 43
	{"last-modified", ""},                // 44
	{"link", ""},                         // 45
	{"location", ""},                     // 46
	{"max-forwards", ""},                 // 47
	{"proxy-authenticate", ""},           // 48
	{"proxy-authorization", ""},          // 49
	{"range", ""},                        // 50
	{"referer", ""},                      // 51
	{"refresh", ""},                      // 52
	{"retry-after", ""},                  // 53
	{"server", ""},                       // 54
	{"set-cookie", ""},                   // 55
	{"strict-transport-security", ""},    // 56
	{"transfer-encoding", ""},            // 57
	{"user-agent", ""},                   // 58
	{"vary", ""},                         // 59
	{"via", ""},                          // 60
	{"www-authenticate", ""},             // 61
}

const staticTableSize = 61

// HPACKEncoder implements HPACK encoding as per RFC 7541
type HPACKEncoder struct {
	dynamicTable   []HeaderField
	dynamicSize    uint32
	maxDynamicSize uint32
}

// HPACKDecoder implements HPACK decoding as per RFC 7541
type HPACKDecoder struct {
	dynamicTable   []HeaderField
	dynamicSize    uint32
	maxDynamicSize uint32
}

// NewHPACKEncoder creates a new HPACK encoder
func NewHPACKEncoder() *HPACKEncoder {
	return &HPACKEncoder{
		dynamicTable:   make([]HeaderField, 0),
		dynamicSize:    0,
		maxDynamicSize: 4096, // Default as per RFC 7541
	}
}

// NewHPACKDecoder creates a new HPACK decoder
func NewHPACKDecoder() *HPACKDecoder {
	return &HPACKDecoder{
		dynamicTable:   make([]HeaderField, 0),
		dynamicSize:    0,
		maxDynamicSize: 4096, // Default as per RFC 7541
	}
}

// SetMaxDynamicTableSize updates maximum dynamic table size
func (e *HPACKEncoder) SetMaxDynamicTableSize(size uint32) {
	e.maxDynamicSize = size
	e.evictEntries()
}

// SetMaxDynamicTableSize updates maximum dynamic table size
func (d *HPACKDecoder) SetMaxDynamicTableSize(size uint32) {
	d.maxDynamicSize = size
	d.evictEntries()
}

// Encode encodes a list of header fields using HPACK as per RFC 7541
func (e *HPACKEncoder) Encode(headers map[string]string) ([]byte, error) {
	var buf bytes.Buffer

	for name, value := range headers {
		headerField := HeaderField{Name: name, Value: value}

		// Try indexed header field representation (Section 6.1)
		if index := e.findExactMatch(headerField); index > 0 {
			e.writeIndexedHeaderField(&buf, index)
			continue
		}

		// Try literal header field with incremental indexing (Section 6.2.1)
		if nameIndex := e.findNameMatch(name); nameIndex > 0 {
			e.writeLiteralHeaderFieldWithIndexing(&buf, nameIndex, value)
		} else {
			e.writeLiteralHeaderFieldWithIndexingNewName(&buf, name, value)
		}

		// Add to dynamic table as per Section 2.3.2
		e.addToDynamicTable(headerField)
	}

	return buf.Bytes(), nil
}

// Decode decodes HPACK-encoded header block as per RFC 7541 Section 3
func (d *HPACKDecoder) Decode(data []byte) (map[string]string, error) {
	headers := make(map[string]string)
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		b, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}

		// Indexed Header Field Representation (Section 6.1)
		if b&0x80 != 0 {
			reader.UnreadByte()
			index, err := d.readInteger(reader, 7)
			if err != nil {
				return nil, err
			}

			if index == 0 {
				return nil, fmt.Errorf("invalid indexed header field with index 0")
			}

			field := d.getHeaderField(index)
			headers[field.Name] = field.Value

			// Literal Header Field with Incremental Indexing (Section 6.2.1)
		} else if b&0x40 != 0 {
			reader.UnreadByte()
			index, err := d.readInteger(reader, 6)
			if err != nil {
				return nil, err
			}

			var name string
			if index == 0 {
				name, err = d.readString(reader)
				if err != nil {
					return nil, err
				}
			} else {
				field := d.getHeaderField(index)
				name = field.Name
			}

			value, err := d.readString(reader)
			if err != nil {
				return nil, err
			}

			headers[name] = value
			d.addToDynamicTable(HeaderField{Name: name, Value: value})

			// Literal Header Field without Indexing (Section 6.2.2)
		} else if b&0x20 == 0 && b&0x10 == 0 {
			reader.UnreadByte()
			index, err := d.readInteger(reader, 4)
			if err != nil {
				return nil, err
			}

			var name string
			if index == 0 {
				name, err = d.readString(reader)
				if err != nil {
					return nil, err
				}
			} else {
				field := d.getHeaderField(index)
				name = field.Name
			}

			value, err := d.readString(reader)
			if err != nil {
				return nil, err
			}

			headers[name] = value

			// Literal Header Field Never Indexed (Section 6.2.3)
		} else if b&0x10 != 0 {
			reader.UnreadByte()
			index, err := d.readInteger(reader, 4)
			if err != nil {
				return nil, err
			}

			var name string
			if index == 0 {
				name, err = d.readString(reader)
				if err != nil {
					return nil, err
				}
			} else {
				field := d.getHeaderField(index)
				name = field.Name
			}

			value, err := d.readString(reader)
			if err != nil {
				return nil, err
			}

			headers[name] = value

			// Dynamic Table Size Update (Section 6.3)
		} else if b&0x20 != 0 {
			reader.UnreadByte()
			maxSize, err := d.readInteger(reader, 5)
			if err != nil {
				return nil, err
			}
			d.SetMaxDynamicTableSize(uint32(maxSize))

		} else {
			return nil, fmt.Errorf("unknown header field representation pattern")
		}
	}

	return headers, nil
}

// writeIndexedHeaderField writes an indexed header field as per RFC 7541 Section 6.1
func (e *HPACKEncoder) writeIndexedHeaderField(buf *bytes.Buffer, index int) {
	e.writeInteger(buf, index, 7, 0x80)
}

// writeLiteralHeaderFieldWithIndexing writes literal header field with incremental indexing
func (e *HPACKEncoder) writeLiteralHeaderFieldWithIndexing(buf *bytes.Buffer, nameIndex int, value string) {
	e.writeInteger(buf, nameIndex, 6, 0x40)
	e.writeString(buf, value, false) // No Huffman encoding for simplicity
}

// writeLiteralHeaderFieldWithIndexingNewName writes literal header field with new name
func (e *HPACKEncoder) writeLiteralHeaderFieldWithIndexingNewName(buf *bytes.Buffer, name, value string) {
	buf.WriteByte(0x40) // 01000000 pattern
	e.writeString(buf, name, false)
	e.writeString(buf, value, false)
}

// findExactMatch searches for exact header field match in static and dynamic tables
func (e *HPACKEncoder) findExactMatch(field HeaderField) int {
	// Search static table
	for i := 1; i <= staticTableSize; i++ {
		if staticTable[i].Name == field.Name && staticTable[i].Value == field.Value {
			return i
		}
	}

	// Search dynamic table
	for i, dynField := range e.dynamicTable {
		if dynField.Name == field.Name && dynField.Value == field.Value {
			return staticTableSize + 1 + i
		}
	}

	return 0
}

// findNameMatch searches for header field name match
func (e *HPACKEncoder) findNameMatch(name string) int {
	// Search static table
	for i := 1; i <= staticTableSize; i++ {
		if staticTable[i].Name == name {
			return i
		}
	}

	// Search dynamic table
	for i, field := range e.dynamicTable {
		if field.Name == name {
			return staticTableSize + 1 + i
		}
	}

	return 0
}

// getHeaderField retrieves header field by index from combined address space
func (d *HPACKDecoder) getHeaderField(index int) HeaderField {
	if index <= staticTableSize {
		return staticTable[index]
	}

	dynamicIndex := index - staticTableSize - 1
	if dynamicIndex < len(d.dynamicTable) {
		return d.dynamicTable[dynamicIndex]
	}

	return HeaderField{"", ""} // Should not happen with valid input
}

// addToDynamicTable adds entry to dynamic table as per RFC 7541 Section 2.3.2
func (e *HPACKEncoder) addToDynamicTable(field HeaderField) {
	entrySize := e.calculateEntrySize(field)

	// Evict entries if needed as per Section 4.4
	for e.dynamicSize+entrySize > e.maxDynamicSize && len(e.dynamicTable) > 0 {
		e.evictOldest()
	}

	// Add new entry at beginning (newest entries have lowest index)
	if entrySize <= e.maxDynamicSize {
		e.dynamicTable = append([]HeaderField{field}, e.dynamicTable...)
		e.dynamicSize += entrySize
	}
}

// addToDynamicTable adds entry to dynamic table for decoder
func (d *HPACKDecoder) addToDynamicTable(field HeaderField) {
	entrySize := d.calculateEntrySize(field)

	// Evict entries if needed
	for d.dynamicSize+entrySize > d.maxDynamicSize && len(d.dynamicTable) > 0 {
		d.evictOldest()
	}

	// Add new entry at beginning
	if entrySize <= d.maxDynamicSize {
		d.dynamicTable = append([]HeaderField{field}, d.dynamicTable...)
		d.dynamicSize += entrySize
	}
}

// calculateEntrySize calculates size of dynamic table entry as per RFC 7541 Section 4.1
func (e *HPACKEncoder) calculateEntrySize(field HeaderField) uint32 {
	return uint32(len(field.Name) + len(field.Value) + 32)
}

func (d *HPACKDecoder) calculateEntrySize(field HeaderField) uint32 {
	return uint32(len(field.Name) + len(field.Value) + 32)
}

// evictOldest removes oldest entry from dynamic table
func (e *HPACKEncoder) evictOldest() {
	if len(e.dynamicTable) > 0 {
		oldest := e.dynamicTable[len(e.dynamicTable)-1]
		e.dynamicSize -= e.calculateEntrySize(oldest)
		e.dynamicTable = e.dynamicTable[:len(e.dynamicTable)-1]
	}
}

func (d *HPACKDecoder) evictOldest() {
	if len(d.dynamicTable) > 0 {
		oldest := d.dynamicTable[len(d.dynamicTable)-1]
		d.dynamicSize -= d.calculateEntrySize(oldest)
		d.dynamicTable = d.dynamicTable[:len(d.dynamicTable)-1]
	}
}

// evictEntries evicts entries when max table size changes as per Section 4.3
func (e *HPACKEncoder) evictEntries() {
	for e.dynamicSize > e.maxDynamicSize && len(e.dynamicTable) > 0 {
		e.evictOldest()
	}
}

func (d *HPACKDecoder) evictEntries() {
	for d.dynamicSize > d.maxDynamicSize && len(d.dynamicTable) > 0 {
		d.evictOldest()
	}
}

// writeInteger writes an integer using HPACK integer encoding as per RFC 7541 Section 5.1
func (e *HPACKEncoder) writeInteger(buf *bytes.Buffer, value int, n int, prefix byte) {
	max := (1 << n) - 1

	if value < max {
		buf.WriteByte(prefix | byte(value))
	} else {
		buf.WriteByte(prefix | byte(max))
		value -= max

		for value >= 128 {
			buf.WriteByte(byte(value%128 + 128))
			value /= 128
		}
		buf.WriteByte(byte(value))
	}
}

// readInteger reads an integer using HPACK integer encoding as per RFC 7541 Section 5.1
func (d *HPACKDecoder) readInteger(reader io.ByteReader, n int) (int, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return 0, err
	}

	max := (1 << n) - 1
	mask := byte(max)
	value := int(b & mask)

	if value < max {
		return value, nil
	}

	m := 0
	for {
		b, err := reader.ReadByte()
		if err != nil {
			return 0, err
		}
		value += int(b&127) << m
		m += 7
		if b&128 == 0 {
			break
		}
	}

	return value, nil
}

// writeString writes a string using HPACK string encoding as per RFC 7541 Section 5.2
func (e *HPACKEncoder) writeString(buf *bytes.Buffer, s string, huffman bool) {
	data := []byte(s)

	// Write string length with H flag
	prefix := byte(0)
	if huffman {
		prefix = 0x80
	}

	e.writeInteger(buf, len(data), 7, prefix)
	buf.Write(data)
}

// readString reads a string using HPACK string encoding as per RFC 7541 Section 5.2
func (d *HPACKDecoder) readString(reader io.ByteReader) (string, error) {
	b, err := reader.ReadByte()
	if err != nil {
		return "", err
	}

	huffmanEncoded := (b & 0x80) != 0

	// Unread the byte to let readInteger handle it
	if br, ok := reader.(*bytes.Reader); ok {
		br.UnreadByte()
	}

	length, err := d.readInteger(reader, 7)
	if err != nil {
		return "", err
	}

	data := make([]byte, length)
	for i := 0; i < length; i++ {
		b, err := reader.ReadByte()
		if err != nil {
			return "", err
		}
		data[i] = b
	}

	if huffmanEncoded {
		// For simplicity, we don't implement Huffman decoding here
		// In a complete implementation, this would decode using the Huffman table
		return string(data), nil
	}

	return string(data), nil
}
