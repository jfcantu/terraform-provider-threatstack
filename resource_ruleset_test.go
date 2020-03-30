package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/jfcantu/threatstack-golang/threatstack"
	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform/helper/acctest"
)

func init() {
	resource.AddTestSweepers("threatstack_ruleset", &resource.Sweeper{
		Name: "threatstack_ruleset",
		F:    sweepRulesets,
	})
}

func TestAccThreatstackRuleset_basic(test *testing.T) {
	rsName := fmt.Sprintf("tf%s", acctest.RandString(5))
	rsDesc := fmt.Sprintf("tf%s", acctest.RandString(5))

	resource.Test(test, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(test) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckThreatstackRulesetDestroyed,
		Steps: []resource.TestStep{
			{
				Config: testAccThreatstackRuleset(rsName, rsDesc),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRulesetExists("threatstack_ruleset.test"),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "name", rsName),
					resource.TestCheckResourceAttr("threatstack_ruleset.test", "description", rsDesc),
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

func testAccCheckThreatstackRulesetDestroyed(s *terraform.State) error {
	cli := testAccProvider.Meta().(*threatstack.Client)

	for _, res := range s.RootModule().Resources {
		if res.Type != "threatstack_ruleset" {
			continue
		}

		_, err := cli.Rulesets.Get(res.Primary.ID)
		if err == nil {
			return fmt.Errorf("Ruleset %s still exists", res.Primary.ID)
		}

		if !strings.Contains(err.Error(), "404") {
			return err
		}
	}

	return nil
}

func testAccThreatstackRuleset(name, desc string) string {
	return fmt.Sprintf(`
resource "threatstack_ruleset" "test" {
	name = "%s"

	description = "%s"
}
`, name, desc)
}
