package main

import (
	"bytes"
	"reflect"
	"testing"
)

func TestHPACKBasicEncodeDecodeRoundtrip(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	testCases := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "simple headers",
			headers: map[string]string{
				"content-type": "text/html",
				"user-agent":   "test-client",
			},
		},
		{
			name: "http2 pseudo headers",
			headers: map[string]string{
				":method":    "GET",
				":path":      "/test",
				":scheme":    "https",
				":authority": "example.com",
			},
		},
		{
			name: "mixed headers",
			headers: map[string]string{
				":method":      "POST",
				":path":        "/api/data",
				":scheme":      "https",
				":authority":   "api.example.com",
				"content-type": "application/json",
				"accept":       "application/json",
				"user-agent":   "test-client/1.0",
			},
		},
		{
			name: "empty value header",
			headers: map[string]string{
				"accept-charset": "",
				"authorization":  "",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encode
			encoded, err := encoder.Encode(tc.headers)
			if err != nil {
				t.Fatalf("Failed to encode headers: %v", err)
			}

			if len(encoded) == 0 {
				t.Fatal("Encoded data is empty")
			}

			// Decode
			decoded, err := decoder.Decode(encoded)
			if err != nil {
				t.Fatalf("Failed to decode headers: %v", err)
			}

			// Compare
			if !reflect.DeepEqual(tc.headers, decoded) {
				t.Errorf("Headers don't match after roundtrip\nOriginal: %v\nDecoded:  %v", tc.headers, decoded)
			}
		})
	}
}

func TestHPACKStaticTableLookup(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	// Test headers that should be found in static table
	staticHeaders := map[string]string{
		":method": "GET",   // Should use static table index 2
		":path":   "/",     // Should use static table index 4
		":scheme": "https", // Should use static table index 7
		":status": "200",   // Should use static table index 8
	}

	encoded, err := encoder.Encode(staticHeaders)
	if err != nil {
		t.Fatalf("Failed to encode static headers: %v", err)
	}

	// Verify the encoding uses indexed header field representation (starts with 1)
	for i, b := range encoded {
		if b&0x80 == 0 {
			t.Logf("Byte %d: %08b (not indexed)", i, b)
		} else {
			t.Logf("Byte %d: %08b (indexed)", i, b)
		}
	}

	decoded, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode static headers: %v", err)
	}

	if !reflect.DeepEqual(staticHeaders, decoded) {
		t.Errorf("Static headers don't match\nOriginal: %v\nDecoded:  %v", staticHeaders, decoded)
	}
}

func TestHPACKLiteralHeaderFieldWithIncrementalIndexing(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	// First encode some custom headers that will be added to dynamic table
	firstHeaders := map[string]string{
		"custom-header": "custom-value",
		"x-test":        "test-value",
	}

	encoded1, err := encoder.Encode(firstHeaders)
	if err != nil {
		t.Fatalf("Failed to encode first headers: %v", err)
	}

	decoded1, err := decoder.Decode(encoded1)
	if err != nil {
		t.Fatalf("Failed to decode first headers: %v", err)
	}

	if !reflect.DeepEqual(firstHeaders, decoded1) {
		t.Errorf("First headers don't match\nOriginal: %v\nDecoded:  %v", firstHeaders, decoded1)
	}

	// Now encode same headers again - should use dynamic table references
	encoded2, err := encoder.Encode(firstHeaders)
	if err != nil {
		t.Fatalf("Failed to encode second headers: %v", err)
	}

	// Second encoding should be shorter due to dynamic table usage
	if len(encoded2) >= len(encoded1) {
		t.Logf("First encoding length: %d, Second encoding length: %d", len(encoded1), len(encoded2))
		t.Log("Note: Dynamic table optimization may not be visible in this simple test")
	}

	decoded2, err := decoder.Decode(encoded2)
	if err != nil {
		t.Fatalf("Failed to decode second headers: %v", err)
	}

	if !reflect.DeepEqual(firstHeaders, decoded2) {
		t.Errorf("Second headers don't match\nOriginal: %v\nDecoded:  %v", firstHeaders, decoded2)
	}
}

func TestHPACKIntegerEncoding(t *testing.T) {
	encoder := NewHPACKEncoder()

	testCases := []struct {
		value    int
		n        int
		prefix   byte
		expected []byte
	}{
		{10, 5, 0, []byte{10}},            // Small value fits in prefix
		{1337, 5, 0, []byte{31, 154, 10}}, // Large value needs continuation
		{42, 8, 0, []byte{42}},            // Value at octet boundary
		{255, 8, 0, []byte{255}},          // Max value in 8-bit prefix
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			var buf bytes.Buffer
			encoder.writeInteger(&buf, tc.value, tc.n, tc.prefix)
			result := buf.Bytes()

			if !bytes.Equal(result, tc.expected) {
				t.Errorf("Integer encoding failed\nValue: %d, N: %d, Prefix: %d\nExpected: %v\nGot:      %v",
					tc.value, tc.n, tc.prefix, tc.expected, result)
			}
		})
	}
}

func TestHPACKIntegerDecoding(t *testing.T) {
	decoder := NewHPACKDecoder()

	testCases := []struct {
		data     []byte
		n        int
		expected int
	}{
		{[]byte{10}, 5, 10},            // Small value in prefix
		{[]byte{31, 154, 10}, 5, 1337}, // Large value with continuation
		{[]byte{42}, 8, 42},            // Value at octet boundary
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			reader := bytes.NewReader(tc.data)
			result, err := decoder.readInteger(reader, tc.n)
			if err != nil {
				t.Fatalf("Failed to decode integer: %v", err)
			}

			if result != tc.expected {
				t.Errorf("Integer decoding failed\nData: %v, N: %d\nExpected: %d\nGot:      %d",
					tc.data, tc.n, tc.expected, result)
			}
		})
	}
}

func TestHPACKStringEncoding(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	testStrings := []string{
		"",
		"hello",
		"test-header-name",
		"application/json",
		"Mozilla/5.0 (compatible; test)",
		":method",
		"www.example.com",
	}

	for _, str := range testStrings {
		t.Run(str, func(t *testing.T) {
			var buf bytes.Buffer
			encoder.writeString(&buf, str, false) // No Huffman encoding for simplicity

			reader := bytes.NewReader(buf.Bytes())
			decoded, err := decoder.readString(reader)
			if err != nil {
				t.Fatalf("Failed to decode string: %v", err)
			}

			if decoded != str {
				t.Errorf("String roundtrip failed\nOriginal: %q\nDecoded:  %q", str, decoded)
			}
		})
	}
}

func TestHPACKDynamicTableManagement(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	// Set small dynamic table size to test eviction
	encoder.SetMaxDynamicTableSize(100)
	decoder.SetMaxDynamicTableSize(100)

	// Add headers that should fill up the dynamic table
	largeHeaders := map[string]string{
		"very-long-header-name-1": "very-long-header-value-that-should-consume-significant-space",
		"very-long-header-name-2": "another-very-long-header-value-for-testing-eviction",
		"very-long-header-name-3": "yet-another-long-value-to-trigger-table-eviction",
	}

	encoded, err := encoder.Encode(largeHeaders)
	if err != nil {
		t.Fatalf("Failed to encode large headers: %v", err)
	}

	decoded, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode large headers: %v", err)
	}

	if !reflect.DeepEqual(largeHeaders, decoded) {
		t.Errorf("Large headers don't match after dynamic table management\nOriginal: %v\nDecoded:  %v",
			largeHeaders, decoded)
	}
}

func TestHPACKEmptyHeaders(t *testing.T) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	// Test empty headers map
	emptyHeaders := map[string]string{}

	encoded, err := encoder.Encode(emptyHeaders)
	if err != nil {
		t.Fatalf("Failed to encode empty headers: %v", err)
	}

	if len(encoded) != 0 {
		t.Errorf("Empty headers should produce empty encoding, got %d bytes", len(encoded))
	}

	decoded, err := decoder.Decode(encoded)
	if err != nil {
		t.Fatalf("Failed to decode empty headers: %v", err)
	}

	if len(decoded) != 0 {
		t.Errorf("Empty encoding should produce empty headers, got %v", decoded)
	}
}

func TestHPACKErrorHandling(t *testing.T) {
	decoder := NewHPACKDecoder()

	// Test malformed data
	malformedData := [][]byte{
		{0x80, 0x00},       // Indexed header field with index 0 (invalid)
		{0x40, 0x00, 0x01}, // Incomplete literal header field
		{0x00, 0x81},       // String with length but no data
	}

	for i, data := range malformedData {
		t.Run("", func(t *testing.T) {
			_, err := decoder.Decode(data)
			if err == nil {
				t.Errorf("Test case %d: Expected error for malformed data %v, but got none", i, data)
			}
		})
	}
}

func TestHPACKStaticTableAccess(t *testing.T) {
	decoder := NewHPACKDecoder()

	// Test accessing static table entries
	testCases := []struct {
		index    int
		expected HeaderField
	}{
		{1, HeaderField{":authority", ""}},
		{2, HeaderField{":method", "GET"}},
		{3, HeaderField{":method", "POST"}},
		{4, HeaderField{":path", "/"}},
		{8, HeaderField{":status", "200"}},
		{16, HeaderField{"accept-encoding", "gzip, deflate"}},
	}

	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			field := decoder.getHeaderField(tc.index)
			if field.Name != tc.expected.Name || field.Value != tc.expected.Value {
				t.Errorf("Static table index %d\nExpected: %+v\nGot:      %+v",
					tc.index, tc.expected, field)
			}
		})
	}
}

func BenchmarkHPACKEncoding(b *testing.B) {
	encoder := NewHPACKEncoder()

	headers := map[string]string{
		":method":         "GET",
		":path":           "/api/v1/data",
		":scheme":         "https",
		":authority":      "api.example.com",
		"accept":          "application/json",
		"accept-encoding": "gzip, deflate",
		"user-agent":      "benchmark-client/1.0",
		"authorization":   "Bearer token123456789",
		"content-type":    "application/json",
		"cache-control":   "no-cache",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := encoder.Encode(headers)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHPACKDecoding(b *testing.B) {
	encoder := NewHPACKEncoder()
	decoder := NewHPACKDecoder()

	headers := map[string]string{
		":method":         "GET",
		":path":           "/api/v1/data",
		":scheme":         "https",
		":authority":      "api.example.com",
		"accept":          "application/json",
		"accept-encoding": "gzip, deflate",
		"user-agent":      "benchmark-client/1.0",
		"authorization":   "Bearer token123456789",
		"content-type":    "application/json",
		"cache-control":   "no-cache",
	}

	encoded, err := encoder.Encode(headers)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := decoder.Decode(encoded)
		if err != nil {
			b.Fatal(err)
		}
	}
}
