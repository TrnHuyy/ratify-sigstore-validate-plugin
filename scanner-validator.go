package main

import (
	"fmt"
	"strings"
)

func validateGrype(scanner map[string]interface{}) (bool, string) {

	result := scanner["result"].(map[string]interface{})

	matches, ok := result["matches"].([]interface{})
	if !ok {
		return true, "no vulnerabilities"
	}

	critical := 0
	high := 0

	for _, m := range matches {

		match := m.(map[string]interface{})
		vuln := match["vulnerability"].(map[string]interface{})
		severity := strings.ToUpper(vuln["severity"].(string))

		if severity == "CRITICAL" {
			critical++
		}

		if severity == "HIGH" {
			high++
		}
	}

	if critical > 0 || high > 20 {
		return false, fmt.Sprintf(
			"grype vulnerabilities critical=%d high=%d",
			critical,
			high,
		)
	}

	return true, "grype scan clean"
}

func validateTwistlock(scanner map[string]interface{}) (bool, string) {

	result := scanner["result"].(map[string]interface{})
	results := result["results"].([]interface{})
	first := results[0].(map[string]interface{})

	scanPassed := first["vulnerabilityScanPassed"].(bool)
	if !scanPassed {
		return false, "twistlock vulnerability scan failed"
	}

	dist := first["vulnerabilityDistribution"].(map[string]interface{})

	critical := int(dist["critical"].(float64))
	high := int(dist["high"].(float64))

	if !scanPassed || critical > 0 || high > 0 {
		return false, fmt.Sprintf(
			"twistlock vulnerabilities critical=%d high=%d",
			critical,
			high,
		)
	}

	return true, "twistlock scan clean"
}
