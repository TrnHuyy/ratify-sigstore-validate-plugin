package main

type PluginConfig struct {
	Name            string   `json:"name"`
	AllowedPrefixes []string `json:"allowedPrefixes"`
}

type PluginInputConfig struct {
	Config PluginConfig `json:"config"`
}

// type SigstoreBundle struct {
// 	DSSEEnvelope struct {
// 		Payload     string `json:"payload"`
// 		PayloadType string `json:"payloadType"`
// 	} `json:"dsseEnvelope"`
// }

type SigstoreBundle struct {
	VerificationMaterial struct {
		Certificate struct {
			RawBytes string `json:"rawBytes"`
		} `json:"certificate"`
	} `json:"verificationMaterial"`

	DsseEnvelope struct {
		Payload     string `json:"payload"`
		PayloadType string `json:"payloadType"`
		Signatures  []struct {
			Sig string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

const (
	SLSAPredicate = "https://slsa.dev/provenance/v1"
	VulnPredicate = "https://in-toto.io/attestation/vulns/v0.2"

	GrypeScanner     = "https://github.com/anchore/grype"
	TwistlockScanner = "https://www.paloaltonetworks.com/prisma/cloud"
)
