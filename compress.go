package cms

import (
	"bytes"
	"compress/zlib"
	"encoding/asn1"
)

type compressedData struct {
	Version              int
	CompressionAlgorithm asn1.ObjectIdentifier
	EncapContentInfo     encapsulatedContentInfo
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     []byte `asn1:"explicit,optional,tag:0"` // need not be DER encoded
}

func Compress(data []byte) ([]byte, error) {
	// 1. compress using zlib
	buf := new(bytes.Buffer)
	w := zlib.NewWriter(buf)
	defer w.Close()
	_, err := w.Write(data)
	if err != nil {
		return nil, err
	}
	compressedBytes := buf.Bytes()

	// 2. wrap to EncapsulatedContentInfo
	encapsulated := encapsulatedContentInfo{
		EContentType: OIDCompressedData,
		EContent:     compressedBytes,
	}

	// 3. wrap to CompressedData
	compressed := compressedData{
		Version:              0,
		CompressionAlgorithm: OIDCompressionAlgorithmZLIB,
		EncapContentInfo:     encapsulated,
	}
	compressedMarshalled, err := asn1.Marshal(compressed)
	if err != nil {
		return nil, err
	}

	// 3. wrap to ContentInfo
	contentInfo := contentInfo{
		ContentType: OIDCompressedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: compressedMarshalled},
	}

	// 4. return DER encoded ContentInfo
	return asn1.Marshal(contentInfo)
}
