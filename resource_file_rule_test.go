package main

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

func init() {
	resource.AddTestSweepers("threatstack_file_rule", &resource.Sweeper{
		Name: "threatstack_file_rule",
		F:    sweepRulesets,
	})
}

func TestAccThreatstackFileRule_basic(test *testing.T) {
	resource.Test(test, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(test) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckThreatstackRulesetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccBasicFileRule(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRuleExists("threatstack_file_rule.test"),
				),
			},
		},
	})
}

func testAccBasicFileRule() string {
	return fmt.Sprintf(`
resource "threatstack_file_rule" "test" {
	name = "NAME"
	title = "TITLE"
	description = "DESC"
	ruleset = threatstack_ruleset.test.id
	severity = 1
	aggregate_fields = ["filename"]
	monitor_events=["all"]
	file_path {
		path = "/etc"
		recursive = true
	}
	filter = "event_type = \"file\""
	window = 86400
	threshold = 1
	suppressions = ["event_type != \"file\""]
	enabled = true
	include_tag {
		source = "ec2"
		key = "includekey"
		value = "includevalue"
	}
	exclude_tag {
		source = "ec2"
		key = "excludekey"
		value = "excludevalue"
	}
}

%s
`, testAccThreatstackRuleTestRuleset)
}

const testAccThreatstackRuleTestRuleset = `
resource "threatstack_ruleset" "test" {
	name = "tfRuleTestRuleset"

	description = "Ruleset to hold rules being tested"
}
`
