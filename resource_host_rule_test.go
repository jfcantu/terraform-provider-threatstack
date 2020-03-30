package main

import (
	"fmt"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
)

func init() {
	resource.AddTestSweepers("threatstack_host_rule", &resource.Sweeper{
		Name: "threatstack_host_rule",
		F:    sweepRulesets,
	})
}

func TestAccThreatstackHostRule_basic(test *testing.T) {
	resource.Test(test, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(test) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckThreatstackRulesetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccBasicHostRule(),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRuleExists("threatstack_host_rule.test"),
				),
			},
		},
	})
}

func testAccBasicHostRule() string {
	return fmt.Sprintf(`
resource "threatstack_host_rule" "test" {
	name = "NAME"
	title = "TITLE"
	description = "DESC"
	ruleset = threatstack_ruleset.test.id
	severity = 1
	aggregate_fields = ["user"]
	filter = "event_type = \"host\""
	window = 86400
	threshold = 1
	suppressions = ["event_type != \"host\""]
	enabled = true
}

%s
`, testAccThreatstackRuleTestRuleset)
}
