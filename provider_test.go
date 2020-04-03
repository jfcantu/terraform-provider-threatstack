package main

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	log "github.com/sirupsen/logrus"
)

var testAccProviders map[string]terraform.ResourceProvider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]terraform.ResourceProvider{
		"threatstack": testAccProvider,
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProviderImpl(t *testing.T) {
	var _ terraform.ResourceProvider = Provider()
}

func testAccPreCheck(test *testing.T) {
	if v := os.Getenv("THREATSTACK_API_KEY"); v == "" {
		test.Fatal("THREATSTACK_API_KEY must be set for acceptance tests")
	}
	if v := os.Getenv("THREATSTACK_ORG_ID"); v == "" {
		test.Fatal("THREATSTACK_ORG_ID must be set for acceptance tests")
	}
	if v := os.Getenv("THREATSTACK_USER_ID"); v == "" {
		test.Fatal("THREATSTACK_USER_ID must be set for acceptance tests")
	}
}

func sweepRulesets(region string) error {
	client, err := sharedClient()
	if err != nil {
		return err
	}

	rulesets, err := client.Rulesets.List()
	if err != nil {
		return fmt.Errorf("Error listing rulesets: %s", err.Error())
	}
	for _, ruleset := range rulesets {
		if strings.HasPrefix(ruleset.Name, "tf") {
			err := client.Rulesets.Delete(ruleset.ID)
			if err != nil {
				log.Errorf("Error deleting ruleset %s: %s", ruleset.Name, err.Error())
			}
		}
	}

	return nil
}
