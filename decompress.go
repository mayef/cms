package cms

import (
	"bytes"
	"compress/zlib"
	"encoding/asn1"
	"io"
)

func Decompress(data []byte) ([]byte, error) {
	// 1. parse ContentInfo
	var contentInfo contentInfo
	_, err := asn1.Unmarshal(data, &contentInfo)
	if err != nil {
		return nil, err
	}

	// 2. parse CompressedData
	var compressedData compressedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &compressedData)
	if err != nil {
		return nil, err
	}

	// 3. parse EncapsulatedContentInfo
	var encapsulatedContentInfo encapsulatedContentInfo
	_, err = asn1.Unmarshal(compressedData.EncapContentInfo.EContent, &encapsulatedContentInfo)
	if err != nil {
		return nil, err
	}

	// 4. decompress using zlib
	buf := bytes.NewBuffer(encapsulatedContentInfo.EContent)
	r, err := zlib.NewReader(buf)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
