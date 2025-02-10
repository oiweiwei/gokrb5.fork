package rfc3961

import (
	"bytes"
	"testing"
)

// Test vectors from RFC 3961, Appendix A
/*
   mod-crc-32("foo") =                                     33 bc 32 73
   mod-crc-32("test0123456789") =                          d6 88 3e b8
   mod-crc-32("MASSACHVSETTS INSTITVTE OF TECHNOLOGY") =   f7 80 41 e3
   mod-crc-32(8000) =                                      4b 98 83 3b
   mod-crc-32(0008) =                                      32 88 db 0e
   mod-crc-32(0080) =                                      20 83 b8 ed
   mod-crc-32(80) =                                        20 83 b8 ed
   mod-crc-32(80000000) =                                  3b b6 59 ed
   mod-crc-32(00000001) =                                  96 30 07 77
*/
func TestCRC32(t *testing.T) {

	for _, testCase := range []struct {
		in  string
		out []byte
	}{
		{"foo", []byte{0x33, 0xbc, 0x32, 0x73}},
		{"test0123456789", []byte{0xd6, 0x88, 0x3e, 0xb8}},
		{"MASSACHVSETTS INSTITVTE OF TECHNOLOGY", []byte{0xf7, 0x80, 0x41, 0xe3}},
		{"\x80\x00", []byte{0x4b, 0x98, 0x83, 0x3b}},
		{"\x00\x08", []byte{0x32, 0x88, 0xdb, 0x0e}},
		{"\x00\x80", []byte{0x20, 0x83, 0xb8, 0xed}},
		{"\x80", []byte{0x20, 0x83, 0xb8, 0xed}},
		{"\x80\x00\x00\x00", []byte{0x3b, 0xb6, 0x59, 0xed}},
		{"\x00\x00\x00\x01", []byte{0x96, 0x30, 0x07, 0x77}},
	} {
		h := NewCRC32()
		h.Write([]byte(testCase.in))
		out := h.Sum(nil)
		if !bytes.Equal(out, testCase.out) {
			t.Errorf("CRC32(%X) = %x, want %x", testCase.in, out, testCase.out)
		}
		t.Logf("CRC32(%X) = %x, want %x", testCase.in, out, testCase.out)
	}
}
