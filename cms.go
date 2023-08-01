// Package cms implements parsing and generation of some PKCS#7 structures.
package cms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
)

// PKCS7 Represents a PKCS7 structure
type PKCS7 struct {
	Content      []byte
	Certificates []*x509.Certificate
	CRLs         []x509.RevocationList
	Signers      []signerInfo
	raw          interface{}
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// ErrUnsupportedContentType is returned when a PKCS7 content is not supported.
// Currently only Data (1.2.840.113549.1.7.1), Signed Data (1.2.840.113549.1.7.2),
// and Enveloped Data are supported (1.2.840.113549.1.7.3)
var ErrUnsupportedContentType = errors.New("pkcs7: cannot parse data: unimplemented content type")

type unsignedData []byte

var (
	// Signed Data OIDs
	OIDData                   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData             = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDEncryptedData          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAttributeContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	OIDAttributeMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	OIDAttributeSigningTime   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}

	// Digest Algorithms
	OIDDigestAlgorithmSHA256     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	OIDDigestAlgorithmSHA384     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	OIDDigestAlgorithmSHA512     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	OIDDigestAlgorithmSHA224     = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	OIDDigestAlgorithmSHAT224    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 7}
	OIDDigestAlgorithmSHAT256    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 8}
	OIDDigestAlgorithmSHAT384    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 9}
	OIDDigestAlgorithmSHAT512    = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 10}
	OIDDigestAlgorithmBlake2s256 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1722, 12, 2, 2, 8}
	OIDDigestAlgorithmBlake2b256 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 8}
	OIDDigestAlgorithmBlake2b384 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 12}
	OIDDigestAlgorithmBlake2b512 = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1722, 12, 2, 1, 16}

	// Signature Algorithms
	OIDSignatureAlgorithmRSA       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	OIDSignatureAlgorithmRSAPSS    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	OIDSignatureAlgorithmRSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	OIDSignatureAlgorithmRSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	OIDSignatureAlgorithmRSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	OIDSignatureAlgorithmRSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}

	OIDSignatureAlgorithmRSASHAT224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 13}
	OIDSignatureAlgorithmRSASHAT256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 14}
	OIDSignatureAlgorithmRSASHAT384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 15}
	OIDSignatureAlgorithmRSASHAT512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 16}

	OIDSignatureAlgorithmECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	OIDSignatureAlgorithmECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	OIDSignatureAlgorithmECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	OIDSignatureAlgorithmECDSASHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}

	OIDSignatureAlgorithmECDSASHAT224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 9}
	OIDSignatureAlgorithmECDSASHAT256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 10}
	OIDSignatureAlgorithmECDSASHAT384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 11}
	OIDSignatureAlgorithmECDSASHAT512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 12}

	OIDSignatureAlgorithmED25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

	OIDEncryptionAlgorithmECDSAP256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	OIDEncryptionAlgorithmECDSAP384 = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	OIDEncryptionAlgorithmECDSAP521 = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Encryption Algorithms
	OIDEncryptionAlgorithmDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
	OIDEncryptionAlgorithmDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	OIDEncryptionAlgorithmAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	OIDEncryptionAlgorithmAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	OIDEncryptionAlgorithmAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	OIDEncryptionAlgorithmAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	OIDEncryptionAlgorithmAES192GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	OIDEncryptionAlgorithmAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
)

func getHashForOID(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(OIDDigestAlgorithmSHA256), oid.Equal(OIDSignatureAlgorithmECDSASHA256):
		return crypto.SHA256, nil
	case oid.Equal(OIDDigestAlgorithmSHA384), oid.Equal(OIDSignatureAlgorithmECDSASHA384):
		return crypto.SHA384, nil
	case oid.Equal(OIDDigestAlgorithmSHA512), oid.Equal(OIDSignatureAlgorithmECDSASHA512):
		return crypto.SHA512, nil
	case oid.Equal(OIDDigestAlgorithmSHA224), oid.Equal(OIDSignatureAlgorithmECDSASHA224):
		return crypto.SHA224, nil
	case oid.Equal(OIDDigestAlgorithmSHAT224):
		return crypto.SHA3_224, nil
	case oid.Equal(OIDDigestAlgorithmSHAT256):
		return crypto.SHA3_256, nil
	case oid.Equal(OIDDigestAlgorithmSHAT384):
		return crypto.SHA3_384, nil
	case oid.Equal(OIDDigestAlgorithmSHAT512):
		return crypto.SHA3_512, nil
	case oid.Equal(OIDDigestAlgorithmBlake2s256):
		return crypto.BLAKE2s_256, nil
	case oid.Equal(OIDDigestAlgorithmBlake2b256):
		return crypto.BLAKE2b_256, nil
	case oid.Equal(OIDDigestAlgorithmBlake2b384):
		return crypto.BLAKE2b_384, nil
	case oid.Equal(OIDDigestAlgorithmBlake2b512):
		return crypto.BLAKE2b_512, nil
	}
	return crypto.Hash(0), ErrUnsupportedAlgorithm
}

// getDigestOIDForSignatureAlgorithm takes an x509.SignatureAlgorithm
// and returns the corresponding OID digest algorithm
func getDigestOIDForSignatureAlgorithm(digestAlg x509.SignatureAlgorithm) (asn1.ObjectIdentifier, error) {
	switch digestAlg {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return OIDDigestAlgorithmSHA256, nil
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return OIDDigestAlgorithmSHA384, nil
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return OIDDigestAlgorithmSHA512, nil
	}
	return nil, fmt.Errorf("pkcs7: cannot convert hash to oid, unknown hash algorithm")
}

// getOIDForEncryptionAlgorithm takes the private key type of the signer and
// the OID of a digest algorithm to return the appropriate signerInfo.DigestEncryptionAlgorithm
func getOIDForEncryptionAlgorithm(pkey crypto.PrivateKey, OIDDigestAlg asn1.ObjectIdentifier) (asn1.ObjectIdentifier, error) {
	switch pkey.(type) {
	case *rsa.PrivateKey:
		switch {
		default:
			return OIDSignatureAlgorithmRSA, nil
		case OIDDigestAlg.Equal(OIDSignatureAlgorithmRSA):
			return OIDSignatureAlgorithmRSA, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureAlgorithmRSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDSignatureAlgorithmRSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDSignatureAlgorithmRSASHA512, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA224):
			return OIDSignatureAlgorithmRSASHA224, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT224):
			return OIDSignatureAlgorithmRSASHAT224, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT256):
			return OIDSignatureAlgorithmRSASHAT256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT384):
			return OIDSignatureAlgorithmRSASHAT384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT512):
			return OIDSignatureAlgorithmRSASHAT512, nil
		}
	case *ecdsa.PrivateKey:
		switch {
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA256):
			return OIDSignatureAlgorithmECDSASHA256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA384):
			return OIDSignatureAlgorithmECDSASHA384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA512):
			return OIDSignatureAlgorithmECDSASHA512, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHA224):
			return OIDSignatureAlgorithmECDSASHA224, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT224):
			return OIDSignatureAlgorithmECDSASHAT224, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT256):
			return OIDSignatureAlgorithmECDSASHAT256, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT384):
			return OIDSignatureAlgorithmECDSASHAT384, nil
		case OIDDigestAlg.Equal(OIDDigestAlgorithmSHAT512):
			return OIDSignatureAlgorithmECDSASHAT512, nil
		}
	}
	return nil, fmt.Errorf("pkcs7: cannot convert encryption algorithm to oid, unknown private key type %T", pkey)

}

// Parse decodes a DER encoded PKCS7 package
func Parse(data []byte) (p7 *PKCS7, err error) {
	if len(data) == 0 {
		return nil, errors.New("pkcs7: input data is empty")
	}
	var info contentInfo
	der, err := ber2der(data)
	if err != nil {
		return nil, err
	}
	rest, err := asn1.Unmarshal(der, &info)
	if len(rest) > 0 {
		err = asn1.SyntaxError{Msg: "trailing data"}
		return
	}
	if err != nil {
		return
	}

	// fmt.Printf("--> Content Type: %s", info.ContentType)
	switch {
	case info.ContentType.Equal(OIDSignedData):
		return parseSignedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEnvelopedData):
		return parseEnvelopedData(info.Content.Bytes)
	case info.ContentType.Equal(OIDEncryptedData):
		return parseEncryptedData(info.Content.Bytes)
	}
	return nil, ErrUnsupportedContentType
}

func parseEnvelopedData(data []byte) (*PKCS7, error) {
	var ed envelopedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

func parseEncryptedData(data []byte) (*PKCS7, error) {
	var ed encryptedData
	if _, err := asn1.Unmarshal(data, &ed); err != nil {
		return nil, err
	}
	return &PKCS7{
		raw: ed,
	}, nil
}

func (raw rawCertificates) Parse() ([]*x509.Certificate, error) {
	if len(raw.Raw) == 0 {
		return nil, nil
	}

	var val asn1.RawValue
	if _, err := asn1.Unmarshal(raw.Raw, &val); err != nil {
		return nil, err
	}

	return x509.ParseCertificates(val.Bytes)
}

func isCertMatchForIssuerAndSerial(cert *x509.Certificate, ias issuerAndSerial) bool {
	return cert.SerialNumber.Cmp(ias.SerialNumber) == 0 && bytes.Equal(cert.RawIssuer, ias.IssuerName.FullBytes)
}

// Attribute represents a key value pair attribute. Value must be marshalable byte
// `encoding/asn1`
type Attribute struct {
	Type  asn1.ObjectIdentifier
	Value interface{}
}

type attributes struct {
	types  []asn1.ObjectIdentifier
	values []interface{}
}

// Add adds the attribute, maintaining insertion order
func (attrs *attributes) Add(attrType asn1.ObjectIdentifier, value interface{}) {
	attrs.types = append(attrs.types, attrType)
	attrs.values = append(attrs.values, value)
}

type sortableAttribute struct {
	SortKey   []byte
	Attribute attribute
}

type attributeSet []sortableAttribute

func (sa attributeSet) Len() int {
	return len(sa)
}

func (sa attributeSet) Less(i, j int) bool {
	return bytes.Compare(sa[i].SortKey, sa[j].SortKey) < 0
}

func (sa attributeSet) Swap(i, j int) {
	sa[i], sa[j] = sa[j], sa[i]
}

func (sa attributeSet) Attributes() []attribute {
	attrs := make([]attribute, len(sa))
	for i, attr := range sa {
		attrs[i] = attr.Attribute
	}
	return attrs
}

func (attrs *attributes) ForMarshalling() ([]attribute, error) {
	sortables := make(attributeSet, len(attrs.types))
	for i := range sortables {
		attrType := attrs.types[i]
		attrValue := attrs.values[i]
		asn1Value, err := asn1.Marshal(attrValue)
		if err != nil {
			return nil, err
		}
		attr := attribute{
			Type:  attrType,
			Value: asn1.RawValue{Tag: 17, IsCompound: true, Bytes: asn1Value}, // 17 == SET tag
		}
		encoded, err := asn1.Marshal(attr)
		if err != nil {
			return nil, err
		}
		sortables[i] = sortableAttribute{
			SortKey:   encoded,
			Attribute: attr,
		}
	}
	sort.Sort(sortables)
	return sortables.Attributes(), nil
}
