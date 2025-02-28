package cms

import (
	"bytes"
	"errors"
	"fmt"
)

var encodeIndent = 0

type asn1Object interface {
	EncodeTo(writer *bytes.Buffer) error
}

type asn1Structured struct {
	tagBytes []byte
	content  []asn1Object
}

func (s asn1Structured) EncodeTo(out *bytes.Buffer) error {
	//fmt.Printf("%s--> tag: % X\n", strings.Repeat("| ", encodeIndent), s.tagBytes)
	encodeIndent++
	inner := new(bytes.Buffer)
	for _, obj := range s.content {
		err := obj.EncodeTo(inner)
		if err != nil {
			return err
		}
	}
	encodeIndent--
	out.Write(s.tagBytes)
	encodeLength(out, inner.Len())
	out.Write(inner.Bytes())
	return nil
}

type asn1Primitive struct {
	tagBytes []byte
	length   int
	content  []byte
}

func (p asn1Primitive) EncodeTo(out *bytes.Buffer) error {
	_, err := out.Write(p.tagBytes)
	if err != nil {
		return err
	}
	if err = encodeLength(out, p.length); err != nil {
		return err
	}
	//fmt.Printf("%s--> tag: % X length: %d\n", strings.Repeat("| ", encodeIndent), p.tagBytes, p.length)
	//fmt.Printf("%s--> content length: %d\n", strings.Repeat("| ", encodeIndent), len(p.content))
	out.Write(p.content)

	return nil
}

func ber2der(ber []byte) ([]byte, error) {
	if len(ber) == 0 {
		return nil, errors.New("ber2der: input ber is empty")
	}
	//fmt.Printf("--> ber2der: Transcoding %d bytes\n", len(ber))
	out := new(bytes.Buffer)

	obj, _, err := readObject(ber, 0)
	if err != nil {
		return nil, err
	}
	obj.EncodeTo(out)

	// if offset < len(ber) {
	//	return nil, fmt.Errorf("ber2der: Content longer than expected. Got %d, expected %d", offset, len(ber))
	//}

	return out.Bytes(), nil
}

// encodes lengths that are longer than 127 into string of bytes
func marshalLongLength(out *bytes.Buffer, i int) (err error) {
	n := lengthLength(i)

	for ; n > 0; n-- {
		err = out.WriteByte(byte(i >> uint((n-1)*8)))
		if err != nil {
			return
		}
	}

	return nil
}

// computes the byte length of an encoded length value
func lengthLength(i int) (numBytes int) {
	numBytes = 1
	for i > 255 {
		numBytes++
		i >>= 8
	}
	return
}

// encodes the length in DER format
// If the length fits in 7 bits, the value is encoded directly.
//
// Otherwise, the number of bytes to encode the length is first determined.
// This number is likely to be 4 or less for a 32bit length. This number is
// added to 0x80. The length is encoded in big endian encoding follow after
//
// Examples:
//
//	length | byte 1 | bytes n
//	0      | 0x00   | -
//	120    | 0x78   | -
//	200    | 0x81   | 0xC8
//	500    | 0x82   | 0x01 0xF4
func encodeLength(out *bytes.Buffer, length int) (err error) {
	if length >= 128 {
		l := lengthLength(length)
		err = out.WriteByte(0x80 | byte(l))
		if err != nil {
			return
		}
		err = marshalLongLength(out, length)
		if err != nil {
			return
		}
	} else {
		err = out.WriteByte(byte(length))
		if err != nil {
			return
		}
	}
	return
}

func readObject(ber []byte, offset int) (asn1Object, int, error) {
	berLen := len(ber)
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: offset is after end of ber data")
	}
	tagStart := offset
	b := ber[offset]
	offset++
	if offset >= berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	tag := b & 0x1F // last 5 bits
	if tag == 0x1F {
		tag = 0
		for ber[offset] >= 0x80 {
			tag = tag*128 + ber[offset] - 0x80
			offset++
			if offset > berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
		// jvehent 20170227: this doesn't appear to be used anywhere...
		//tag = tag*128 + ber[offset] - 0x80
		offset++
		if offset > berLen {
			return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
		}
	}
	tagEnd := offset

	kind := b & 0x20
	if kind == 0 {
		debugprint("--> Primitive\n")
	} else {
		debugprint("--> Constructed\n")
	}
	// read length
	var length int
	l := ber[offset]
	offset++
	if offset > berLen {
		return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
	}
	indefinite := false
	if l > 0x80 {
		numberOfBytes := (int)(l & 0x7F)
		if numberOfBytes > 4 { // int is only guaranteed to be 32bit
			return nil, 0, errors.New("ber2der: BER tag length too long")
		}
		if numberOfBytes == 4 && (int)(ber[offset]) > 0x7F {
			return nil, 0, errors.New("ber2der: BER tag length is negative")
		}
		if (int)(ber[offset]) == 0x0 {
			return nil, 0, errors.New("ber2der: BER tag length has leading zero")
		}
		debugprint("--> (compute length) indicator byte: %x\n", l)
		debugprint("--> (compute length) length bytes: % X\n", ber[offset:offset+numberOfBytes])
		for i := 0; i < numberOfBytes; i++ {
			length = length*256 + (int)(ber[offset])
			offset++
			if offset > berLen {
				return nil, 0, errors.New("ber2der: cannot move offset forward, end of ber data reached")
			}
		}
	} else if l == 0x80 {
		indefinite = true
	} else {
		length = (int)(l)
	}
	if length < 0 {
		return nil, 0, errors.New("ber2der: invalid negative value found in BER tag length")
	}
	//fmt.Printf("--> length        : %d\n", length)
	contentEnd := offset + length
	if contentEnd > len(ber) {
		return nil, 0, errors.New("ber2der: BER tag length is more than available data")
	}
	debugprint("--> content start : %d\n", offset)
	debugprint("--> content end   : %d\n", contentEnd)
	debugprint("--> content       : % X\n", ber[offset:contentEnd])
	var obj asn1Object
	if indefinite && kind == 0 {
		return nil, 0, errors.New("ber2der: Indefinite form tag must have constructed encoding")
	}
	if kind == 0 {
		obj = asn1Primitive{
			tagBytes: ber[tagStart:tagEnd],
			length:   length,
			content:  ber[offset:contentEnd],
		}
	} else {
		var subObjects []asn1Object
		for (offset < contentEnd) || indefinite {
			var subObj asn1Object
			var err error
			subObj, offset, err = readObject(ber, offset)
			if err != nil {
				return nil, 0, err
			}
			subObjects = append(subObjects, subObj)

			if indefinite {
				terminated, err := isIndefiniteTermination(ber, offset)
				if err != nil {
					return nil, 0, err
				}

				if terminated {
					break
				}
			}
		}
		obj = asn1Structured{
			tagBytes: ber[tagStart:tagEnd],
			content:  subObjects,
		}
	}

	// Apply indefinite form length with 0x0000 terminator.
	if indefinite {
		contentEnd = offset + 2
	}

	return obj, contentEnd, nil
}

func isIndefiniteTermination(ber []byte, offset int) (bool, error) {
	if len(ber)-offset < 2 {
		return false, errors.New("ber2der: Invalid BER format")
	}

	return bytes.Index(ber[offset:], []byte{0x0, 0x0}) == 0, nil
}

func debugprint(format string, a ...interface{}) {
	//fmt.Printf(format, a)
}

func berOctStr2Bytes(data []byte) ([]byte, error) {
	// Create a variable to store the output byte array.
	output := make([]byte, 0)
	offset := 0

	// Read the first byte of the input byte array and assign it to a variable named tag.
	tag := data[offset]
	offset++
	// constructed octet string
	if tag != 0x24 {
		return nil, fmt.Errorf("berOctStr2Bytes: Expected tag 0x24, got 0x%02x", tag)
	}

	// Move offset to the first byte of the first primitive octet string.
	length := data[offset]
	offset++
	if length&0x8f != 0 {
		lengthLength := int(length & 0x7f)
		l := 0
		for j := 0; j < lengthLength; j++ {
			l = l*256 + int(data[offset])
			offset++
		}
	}

	// Create a loop that iterates until the end of the input byte array or an error is encountered.
	for i := offset; i < len(data); {
		// Read the first byte of the input byte array and assign it to a variable named tag.
		tag := data[i]

		// Check if tag is equal to primitive octet string.
		if tag != 0x04 {
			return nil, fmt.Errorf("berOctStr2Bytes: Expected tag&0x04 != 0, got 0x%02x", tag)
		}

		// Read the second byte of the input byte array and assign it to a variable named length.
		length := data[i+1]

		// Check if length is equal to 0x80, which means the element has an indefinite length.
		if length == 0x80 {
			// Find an end-of-content marker (0x00 0x00) to determine the end of the value.
			var j = i + 2
			if j+1 >= len(data) {
				return nil, errors.New("berOctStr2Bytes: Invalid BER format")
			}
			for j+1 < len(data) {
				if data[j] == 0x00 && data[j+1] == 0x00 {
					break
				}
				j++
			}

			// Append the value bytes to the output byte array.
			output = append(output, data[i+2:j]...)
			i = j + 2
		} else if length&0x80 == 0x80 && length&0x7f != 0 {
			// Check if length has an extended marker.
			// If so, take the low 7 bits of the length as the number of bytes in the extended length.
			// Read the extended length and assign it to a variable named l.
			lengthLength := int(length & 0x7f)
			l := 0
			for j := 0; j < lengthLength; j++ {
				l = l*256 + int(data[i+2+j])
			}

			// Append the value bytes to the output byte array.
			output = append(output, data[i+2+lengthLength:i+2+lengthLength+l]...)
			i = i + 2 + lengthLength + l
		} else {
			// Append the value bytes to the output byte array.
			output = append(output, data[i+2:i+2+int(length)]...)
			i = i + 2 + int(length)
		}
	}

	// Return the output byte array.
	return output, nil
}

func bytes2BerOctStr(data []byte) ([]byte, error) {
	// chunk data into 64k blocks
	var chunks [][]byte
	for len(data) > 0 {
		if len(data) > 65535 {
			chunks = append(chunks, data[:65535])
			data = data[65535:]
		} else {
			chunks = append(chunks, data)
			data = nil
		}
	}
	// create a buffer to store the output
	var buf bytes.Buffer
	// constructed octet string { primitive octet string, primitive octet string, ... }
	// constructe the inner primitive string
	var inner bytes.Buffer
	for _, chunk := range chunks {
		inner.WriteByte(0x04)
		encodeLength(&inner, len(chunk))
		inner.Write(chunk)
	}
	// construct the outer constructed string
	buf.WriteByte(0x24)
	encodeLength(&buf, inner.Len())
	buf.Write(inner.Bytes())
	return buf.Bytes(), nil
}
