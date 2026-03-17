package main

import (
	"context"

	"github.com/ratify-project/ratify/pkg/common"
	"github.com/ratify-project/ratify/pkg/ocispecs"
	"github.com/ratify-project/ratify/pkg/referrerstore"
)

func validateVulnReport(
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

	predicate := statement["predicate"].(map[string]interface{})
	inner := predicate["predicate"].(map[string]interface{})
	scanners := inner["scanners"].([]interface{})

	for _, s := range scanners {

		scanner := s.(map[string]interface{})
		uri := scanner["uri"].(string)

		switch uri {

		case GrypeScanner:
			ok, msg := validateGrype(scanner)
			if !ok {
				return false, msg, nil
			}

		case TwistlockScanner:
			ok, msg := validateTwistlock(scanner)
			if !ok {
				return false, msg, nil
			}
		}
	}

	return true, "vulnerability report validated", nil
}
