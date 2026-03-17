package main

import (
	"context"
	"strings"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
)

func validateSLSA(
	ctx context.Context,
	store referrerstore.ReferrerStore,
	subject common.Reference,
	manifest ocispecs.ReferenceManifest,
) (bool, string, error) {

	statement, err := loadStatement(ctx, store, subject, manifest)
	if err != nil {
		return false, "failed to load statement", err
	}

	if err := validateSubject(statement, subject); err != nil {
		return false, err.Error(), nil
	}

	predicateType := statement["predicateType"].(string)
	if predicateType != SLSAPredicate {
		return false, "unsupported predicateType", nil
	}

	predicate := statement["predicate"].(map[string]interface{})
	runDetails := predicate["runDetails"].(map[string]interface{})
	builder := runDetails["builder"].(map[string]interface{})
	builderID := builder["id"].(string)

	if !strings.HasPrefix(builderID, "https://github.com/amplify-health") {
		return false, "builder not trusted", nil
	}

	return true, "SLSA provenance validated", nil
}
