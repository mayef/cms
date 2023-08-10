package cms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

// fork from crypto/x509

type SignatureAlgorithm int

func (algo SignatureAlgorithm) isRSAPSS() bool {
	switch algo {
	case SHA224WithRSAPSS, SHA256WithRSAPSS, SHA384WithRSAPSS, SHA512WithRSAPSS:
		return true
	default:
		return false
	}
}

const (
	UnknownSignatureAlgorithm SignatureAlgorithm = iota

	MD2WithRSA  // Unsupported.
	MD5WithRSA  // Deprecated.
	SHA1WithRSA // Deprecated.
	SHA224WithRSA
	SHA256WithRSA
	SHA384WithRSA
	SHA512WithRSA
	SHAT224WithRSA
	SHAT256WithRSA
	SHAT384WithRSA
	SHAT512WithRSA
	DSAWithSHA1   // Unsupported.
	DSAWithSHA256 // Unsupported.
	ECDSAWithSHA1 // Deprecated.
	ECDSAWithSHA224
	ECDSAWithSHA256
	ECDSAWithSHA384
	ECDSAWithSHA512
	ECDSAWithSHAT224
	ECDSAWithSHAT256
	ECDSAWithSHAT384
	ECDSAWithSHAT512
	SHA224WithRSAPSS
	SHA256WithRSAPSS
	SHA384WithRSAPSS
	SHA512WithRSAPSS
	SHAT224WithRSAPSS
	SHAT256WithRSAPSS
	SHAT384WithRSAPSS
	SHAT512WithRSAPSS
	PureEd25519
)

var signatureAlgorithmDetails = []struct {
	algo       SignatureAlgorithm
	name       string
	oid        asn1.ObjectIdentifier
	pubKeyAlgo x509.PublicKeyAlgorithm
	hash       crypto.Hash
}{
	// {MD2WithRSA, "MD2-RSA", oidSignatureMD2WithRSA, RSA, crypto.Hash(0) /* no value for MD2 */},
	{MD5WithRSA, "MD5-RSA", OIDSignatureAlgorithmRSAMD5, x509.RSA, crypto.MD5},
	{SHA1WithRSA, "SHA1-RSA", OIDSignatureAlgorithmRSASHA1, x509.RSA, crypto.SHA1},
	{SHA224WithRSA, "SHA224-RSA", OIDSignatureAlgorithmRSASHA224, x509.RSA, crypto.SHA224},
	{SHA256WithRSA, "SHA256-RSA", OIDSignatureAlgorithmRSASHA256, x509.RSA, crypto.SHA256},
	{SHA384WithRSA, "SHA384-RSA", OIDSignatureAlgorithmRSASHA384, x509.RSA, crypto.SHA384},
	{SHA512WithRSA, "SHA512-RSA", OIDSignatureAlgorithmRSASHA512, x509.RSA, crypto.SHA512},
	{SHAT224WithRSA, "SHA3-224-RSA", OIDSignatureAlgorithmRSASHAT224, x509.RSA, crypto.SHA3_224},
	{SHAT256WithRSA, "SHA3-256-RSA", OIDSignatureAlgorithmRSASHAT256, x509.RSA, crypto.SHA3_256},
	{SHAT384WithRSA, "SHA3-384-RSA", OIDSignatureAlgorithmRSASHAT384, x509.RSA, crypto.SHA3_384},
	{SHAT512WithRSA, "SHA3-512-RSA", OIDSignatureAlgorithmRSASHAT512, x509.RSA, crypto.SHA3_512},
	{SHA224WithRSAPSS, "SHA224-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA224},
	{SHA256WithRSAPSS, "SHA256-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA256},
	{SHA384WithRSAPSS, "SHA384-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA384},
	{SHA512WithRSAPSS, "SHA512-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA512},
	{SHAT224WithRSAPSS, "SHA3-224-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA3_224},
	{SHAT256WithRSAPSS, "SHA3-256-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA3_256},
	{SHAT384WithRSAPSS, "SHA3-384-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA3_384},
	{SHAT512WithRSAPSS, "SHA3-512-RSAPSS", OIDSignatureAlgorithmRSAPSS, x509.RSA, crypto.SHA3_512},
	// {DSAWithSHA1, "DSA-SHA1", oidSignatureDSAWithSHA1, DSA, crypto.SHA1},
	// {DSAWithSHA256, "DSA-SHA256", oidSignatureDSAWithSHA256, DSA, crypto.SHA256},
	{ECDSAWithSHA1, "ECDSA-SHA1", OIDSignatureAlgorithmECDSASHA1, x509.ECDSA, crypto.SHA1},
	{ECDSAWithSHA224, "ECDSA-SHA224", OIDSignatureAlgorithmECDSASHA224, x509.ECDSA, crypto.SHA224},
	{ECDSAWithSHA256, "ECDSA-SHA256", OIDSignatureAlgorithmECDSASHA256, x509.ECDSA, crypto.SHA256},
	{ECDSAWithSHA384, "ECDSA-SHA384", OIDSignatureAlgorithmECDSASHA384, x509.ECDSA, crypto.SHA384},
	{ECDSAWithSHA512, "ECDSA-SHA512", OIDSignatureAlgorithmECDSASHA512, x509.ECDSA, crypto.SHA512},
	{ECDSAWithSHAT224, "ECDSA-SHA3-224", OIDSignatureAlgorithmECDSASHAT224, x509.ECDSA, crypto.SHA3_224},
	{ECDSAWithSHAT256, "ECDSA-SHA3-256", OIDSignatureAlgorithmECDSASHAT256, x509.ECDSA, crypto.SHA3_256},
	{ECDSAWithSHAT384, "ECDSA-SHA3-384", OIDSignatureAlgorithmECDSASHAT384, x509.ECDSA, crypto.SHA3_384},
	{ECDSAWithSHAT512, "ECDSA-SHA3-512", OIDSignatureAlgorithmECDSASHAT512, x509.ECDSA, crypto.SHA3_512},
	{PureEd25519, "Ed25519", OIDSignatureAlgorithmED25519, x509.Ed25519, crypto.Hash(0) /* no pre-hashing */},
}

// CheckSignature verifies that signature is a valid signature over signed from
// c's public key.
//
// This is a low-level API that performs no validity checks on the certificate.
//
// [MD5WithRSA] signatures are rejected, while [SHA1WithRSA] and [ECDSAWithSHA1]
// signatures are currently accepted.
func CheckSignature(c *x509.Certificate, algo SignatureAlgorithm, signed, signature []byte) error {
	return checkSignature(algo, signed, signature, c.PublicKey)
}

// checkSignature verifies that signature is a valid signature over signed from
// a crypto.PublicKey.
func checkSignature(algo SignatureAlgorithm, signed, signature []byte, publicKey crypto.PublicKey) (err error) {
	var hashType crypto.Hash
	var pubKeyAlgo x509.PublicKeyAlgorithm

	for _, details := range signatureAlgorithmDetails {
		if details.algo == algo {
			hashType = details.hash
			pubKeyAlgo = details.pubKeyAlgo
		}
	}

	switch hashType {
	case crypto.Hash(0):
		if pubKeyAlgo != x509.Ed25519 {
			return ErrUnsupportedAlgorithm
		}
	// case crypto.MD5:
	// return x509.InsecureAlgorithmError(algo)
	// case crypto.SHA1:
	// return x509.InsecureAlgorithmError(algo)
	default:
		if !hashType.Available() {
			return ErrUnsupportedAlgorithm
		}
		h := hashType.New()
		h.Write(signed)
		signed = h.Sum(nil)
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		if pubKeyAlgo != x509.RSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if algo.isRSAPSS() {
			return rsa.VerifyPSS(pub, hashType, signed, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		} else {
			return rsa.VerifyPKCS1v15(pub, hashType, signed, signature)
		}
	case *ecdsa.PublicKey:
		if pubKeyAlgo != x509.ECDSA {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ecdsa.VerifyASN1(pub, signed, signature) { // TODO: SHOULD NOT USE
			return errors.New("x509: ECDSA verification failure")
		}
		return
	case ed25519.PublicKey: // TODO: SHOULD NOT USE
		if pubKeyAlgo != x509.Ed25519 {
			return signaturePublicKeyAlgoMismatchError(pubKeyAlgo, pub)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return errors.New("x509: Ed25519 verification failure")
		}
		return
	}
	return ErrUnsupportedAlgorithm
}

func signaturePublicKeyAlgoMismatchError(expectedPubKeyAlgo x509.PublicKeyAlgorithm, pubKey any) error {
	return fmt.Errorf("x509: signature algorithm specifies an %s public key, but have public key of type %T", expectedPubKeyAlgo.String(), pubKey)
}
