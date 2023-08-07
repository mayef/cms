package cms

import (
	"bytes"
	"compress/zlib"
	"encoding/asn1"
	"errors"
	"io"
)

var ErrNotCompressedContent = errors.New("pkcs7: content data is not a compressed data type")

func (p7 *PKCS7) Decompress() ([]byte, error) {
	// 1. convert to CompressedData
	compressedData, ok := p7.raw.(compressedData)
	if !ok {
		return nil, ErrNotCompressedContent
	}

	// 2. decode octet string to bytes
	// 2.1 try to decode as BER
	b, err := berOctStr2Bytes(compressedData.EncapContentInfo.EContent.Bytes)
	if err != nil {
		// 2.2 if failed, try to decode as DER
		b = []byte{}
		rest, err := asn1.Unmarshal(compressedData.EncapContentInfo.EContent.Bytes, &b)
		if len(rest) > 0 {
			return nil, asn1.SyntaxError{Msg: "trailing data"}
		}
		if err != nil {
			return nil, err
		}
	}
	// 3. decompress using zlib
	buf := bytes.NewBuffer(b)
	r, err := zlib.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
