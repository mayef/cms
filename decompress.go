package cms

import (
	"bytes"
	"compress/zlib"
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

	// 2. decode ber octet string to bytes
	b, err := berOctStr2Bytes(compressedData.EncapContentInfo.EContent.Bytes)
	if err != nil {
		return nil, err
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
