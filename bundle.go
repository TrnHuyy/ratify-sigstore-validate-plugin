package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
)

func loadStatement(
	ctx context.Context,
	store referrerstore.ReferrerStore,
	subject common.Reference,
	manifest ocispecs.ReferenceManifest,
) (map[string]interface{}, error) {

	blobDigest := manifest.Blobs[0].Digest

	blobData, err := store.GetBlobContent(ctx, subject, blobDigest)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to fetch bundle blob from registry (digest=%s): %w",
			blobDigest.String(),
			err,
		)
	}

	var bundle SigstoreBundle
	if err := json.Unmarshal(blobData, &bundle); err != nil {
		return nil, err
	}

	err = verifyBundleIntegrity(&bundle)
	if err != nil {
		return nil, err
	}

	payloadBytes, err := base64.StdEncoding.DecodeString(bundle.DsseEnvelope.Payload)
	if err != nil {
		return nil, err
	}

	var statement map[string]interface{}
	err = json.Unmarshal(payloadBytes, &statement)

	return statement, err
}

func validateSubject(statement map[string]interface{}, subjectReference common.Reference) error {

	subjects, ok := statement["subject"].([]interface{})
	if !ok || len(subjects) == 0 {
		return fmt.Errorf("statement missing subject")
	}

	subject := subjects[0].(map[string]interface{})

	digestMap := subject["digest"].(map[string]interface{})

	attestedDigest := digestMap["sha256"].(string)

	imageDigest := subjectReference.Digest.Hex()

	if attestedDigest != imageDigest {
		return fmt.Errorf(
			"digest mismatch attestation=%s image=%s",
			attestedDigest,
			imageDigest,
		)
	}

	return nil
}

func verifyBundleIntegrity(bundle *SigstoreBundle) error {

	payload := bundle.DsseEnvelope.Payload
	payloadType := bundle.DsseEnvelope.PayloadType
	sig := bundle.DsseEnvelope.Signatures[0].Sig
	certRaw := bundle.VerificationMaterial.Certificate.RawBytes

	// payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	// if err != nil {
	// 	return fmt.Errorf("payload base64 decode failed: %w", err)
	// }

	payloadBytes, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		return fmt.Errorf("payload base64 decode failed: %w", err)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("signature base64 decode failed: %w", err)
	}

	certBytes, err := base64.StdEncoding.DecodeString(certRaw)
	if err != nil {
		return fmt.Errorf("certificate base64 decode failed: %w", err)
	}

	fmt.Println("DEBUG signature length:", len(sigBytes))

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return fmt.Errorf("certificate parse failed: %w", err)
	}

	fmt.Println("DEBUG cert subject:", cert.Subject)
	fmt.Println("DEBUG cert issuer:", cert.Issuer)

	pubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not ECDSA")
	}

	signingInput := buildDSSEMessage(payloadType, payloadBytes)

	fmt.Println("DEBUG signingInput length:", len(signingInput))

	hash := sha256.Sum256(signingInput)

	ok = ecdsa.VerifyASN1(pubKey, hash[:], sigBytes)

	if !ok {
		return fmt.Errorf("dsse signature verification failed")
	}

	fmt.Println("DEBUG signature verification SUCCESS")

	_ = payloadBytes // payload đã được bảo vệ bởi signature

	return nil
}

// func buildDSSEMessage(payloadType string, payload string) []byte {

// 	pt := []byte(payloadType)
// 	pl := []byte(payload)

// 	msg := fmt.Sprintf(
// 		"DSSEv1 %d %s %d %s",
// 		len(pt),
// 		pt,
// 		len(pl),
// 		pl,
// 	)

// 	fmt.Println("DEBUG DSSE message prefix:", msg[:40])

// 	return []byte(msg)
// }

func buildDSSEMessage(payloadType string, payload []byte) []byte {

	pt := []byte(payloadType)

	msg := []byte("DSSEv1 ")

	msg = append(msg, []byte(fmt.Sprintf("%d ", len(pt)))...)
	msg = append(msg, pt...)
	msg = append(msg, ' ')

	msg = append(msg, []byte(fmt.Sprintf("%d ", len(payload)))...)
	msg = append(msg, payload...)

	fmt.Println("DEBUG DSSE message prefix:", string(msg[:40]))

	return msg
}
