package cms

import (
	"bytes"
	"compress/zlib"
	"crypto/x509/pkix"
	"encoding/asn1"
)

type compressedData struct {
	Version              int
	CompressionAlgorithm pkix.AlgorithmIdentifier
	EncapContentInfo     encapsulatedContentInfo
}

type encapsulatedContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"explicit,optional,tag:0"` // need not be DER encoded
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
	if err := w.Flush(); err != nil {
		return nil, err
	}
	compressedBytes := buf.Bytes()
	// TODO: bytes to ber octet string

	// 2. wrap to EncapsulatedContentInfo
	encapsulated := encapsulatedContentInfo{
		EContentType: OIDData,
		EContent: asn1.RawValue{ // constructed OCTET STRING
			Class:      asn1.ClassUniversal,
			Tag:        asn1.TagOctetString,
			IsCompound: true,
			Bytes:      compressedBytes,
		},
	}

	// 3. wrap to CompressedData
	compressed := compressedData{
		Version: 0,
		CompressionAlgorithm: pkix.AlgorithmIdentifier{
			Algorithm: OIDCompressionAlgorithmZLIB,
		},
		EncapContentInfo: encapsulated,
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
