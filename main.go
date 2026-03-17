package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
	"github.com/ratify-project/ratify/pkg/verifier"
	"github.com/ratify-project/ratify/pkg/verifier/plugin/skel"

	_ "github.com/ratify-project/ratify/pkg/referrerstore/oras"
)

const (
	pluginName    = "sigstore-bundle-verifier"
	pluginVersion = "1.0.0"
)

func main() {
	skel.PluginMain(pluginName, pluginVersion, VerifyReference, []string{pluginVersion})
}

func VerifyReference(
	args *skel.CmdArgs,
	subjectReference common.Reference,
	referenceDescriptor ocispecs.ReferenceDescriptor,
	referrerStore referrerstore.ReferrerStore,
) (*verifier.VerifierResult, error) {

	inputConf := PluginInputConfig{}
	if err := json.Unmarshal(args.StdinData, &inputConf); err != nil {
		return nil, fmt.Errorf("failed to parse stdin: %v", err)
	}

	config := inputConf.Config

	referenceManifest, err := referrerStore.GetReferenceManifest(
		context.TODO(),
		subjectReference,
		referenceDescriptor,
	)
	if err != nil {
		return nil, err
	}

	predicateType := referenceManifest.Annotations["dev.sigstore.bundle.predicateType"]

	var isSuccess bool
	var message string

	switch predicateType {

	case SLSAPredicate:
		isSuccess, message, err = validateSLSA(
			context.TODO(),
			referrerStore,
			subjectReference,
			referenceManifest,
		)

	case VulnPredicate:
		isSuccess, message, err = validateVulnReport(
			context.TODO(),
			referrerStore,
			subjectReference,
			referenceManifest,
		)

	default:
		message = fmt.Sprintf("unsupported predicateType: %s", predicateType)
	}

	if err != nil {
		return nil, err
	}

	return &verifier.VerifierResult{
		Name:      config.Name,
		IsSuccess: isSuccess,
		Message:   message,
	}, nil
}
