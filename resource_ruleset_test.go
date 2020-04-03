package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/jfcantu/threatstack-golang/threatstack"
)

func init() {
	resource.AddTestSweepers("threatstack_ruleset", &resource.Sweeper{
		Name: "threatstack_ruleset",
		F:    sweepRulesets,
	})
}

func TestAccThreatstackRuleset_basic(test *testing.T) {
	testRulesetName := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRulesetDesc := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRulesetName2 := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRulesetDesc2 := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRuleName := fmt.Sprintf("tf%s", acctest.RandString(5))

	resource.Test(test, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(test) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckThreatstackRulesetDestroyed,
		Steps: []resource.TestStep{
			// Step 1: Create ruleset
			{
				Config: testAccThreatstackRulesetSimpleRuleset(testRulesetName, testRulesetDesc),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRulesetExists("threatstack_ruleset.test"),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "name", testRulesetName),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "description", testRulesetDesc),
				),
			},
			// Step 2: Add rule
			{
				Config: testAccThreatstackRulesetSimpleRulesetWithRule(testRulesetName, testRulesetDesc, testRuleName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRulesetHasRule("threatstack_ruleset.test", "threatstack_host_rule.test"),
				),
			},
			// Step 3: Rename rule
			{
				Config: testAccThreatstackRulesetSimpleRulesetWithRule(testRulesetName2, testRulesetDesc2, testRuleName),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRulesetHasRule("threatstack_ruleset.test", "threatstack_host_rule.test"),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "name", testRulesetName2),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "description", testRulesetDesc2),
				),
			},
		},
	})
}

func testAccCheckThreatstackRulesetExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		cli := testAccProvider.Meta().(*threatstack.Client)

		res, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if res.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		if _, err := cli.Rulesets.Get(res.Primary.ID); err != nil {
			return fmt.Errorf("Error retrieving rule: %s", err.Error())
		}

		return nil
	}
}

func testAccCheckThreatstackRulesetHasRule(rulesetName string, ruleName string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rsResource := s.RootModule().Resources[rulesetName]
		ruleResource := s.RootModule().Resources[ruleName]

		ruleset, err := testAccProvider.Meta().(*threatstack.Client).Rulesets.Get(rsResource.Primary.ID)
		if err != nil {
			return err
		}

		for _, v := range ruleset.RuleIDs {
			if v == ruleResource.Primary.ID {
				return nil
			}
		}

		return fmt.Errorf("Rule ID %s not found in rules for %s", ruleResource.Primary.ID, rulesetName)
	}
}

func testAccCheckThreatstackRulesetDestroyed(s *terraform.State) error {
	cli := testAccProvider.Meta().(*threatstack.Client)

	for _, res := range s.RootModule().Resources {
		if res.Type != "threatstack_ruleset" {
			continue
		}

		_, err := cli.Rulesets.Get(res.Primary.ID)
		if err == nil {
			return fmt.Errorf("Ruleset ID %s still exists", res.Primary.ID)
		}

		if !strings.Contains(err.Error(), "404") {
			return err
		}
	}

	return nil
}

// Test definitions

// Test 1: Define simple ruleset
func testAccThreatstackRulesetSimpleRuleset(rsName, rsDesc string) string {
	return fmt.Sprintf(`
resource "threatstack_ruleset" "test" {
	name = "%s"

	description = "%s"
}
`, rsName, rsDesc)
}

// Test 2: Add simple rule to ruleset
func testAccThreatstackRulesetSimpleRulesetWithRule(rsName, rsDesc, ruleName string) string {
	return fmt.Sprintf(`
resource "threatstack_ruleset" "test" {
	name = "%s"

	description = "%s"
}

resource "threatstack_host_rule" "test" {
		name = "%s"
		title = "TEST"
		description = "TEST"
		ruleset = threatstack_ruleset.test.id
		severity = 1
		aggregate_fields = ["user"]
		filter = "event_type = \"host\""
		window = 86400
		threshold = 1
		suppressions = ["event_type != \"host\""]
		enabled = true
	}
`, rsName, rsDesc, ruleName)
}
