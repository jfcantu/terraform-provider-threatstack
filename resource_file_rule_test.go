package main

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform/helper/acctest"
)

func init() {
	resource.AddTestSweepers("threatstack_file_rule", &resource.Sweeper{
		Name: "threatstack_file_rule",
		F:    sweepRulesets,
	})
}

func TestAccThreatstackFileRule_basic(test *testing.T) {
	testRuleName := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRuleTitle := fmt.Sprintf("tf%s", acctest.RandString(5))
	testRuleDesc := fmt.Sprintf("tf%s", acctest.RandString(50))
	// TODO: Switch to acctest.RandIntRange() once it's fixed
	// https://github.com/hashicorp/terraform-plugin-sdk/issues/171
	testRuleSeverity := 1

	resource.Test(test, resource.TestCase{
		PreCheck:     func() { testAccPreCheck(test) },
		Providers:    testAccProviders,
		CheckDestroy: testAccCheckThreatstackRulesetDestroyed,
		Steps: []resource.TestStep{
			// Step 1: Create FIM rule
			{
				Config: fmt.Sprintf("%s\n%s",
					testAccBasicFileRule(testRuleName, testRuleTitle, testRuleDesc, testRuleSeverity),
					testAccThreatstackRuleTestRuleset(),
				),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRuleExists("threatstack_file_rule.test"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "name", testRuleName),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "title", testRuleTitle),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "description", testRuleDesc),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "severity", strconv.Itoa(testRuleSeverity)),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.#", "2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.3795442318", "command"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.1592629399", "filename"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "monitor_events.2605756593", "all"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.#", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.path", "/etc"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.recursive", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "filter", `event_type = "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "window", "86400"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "threshold", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.#", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.3891228369", `event_type != "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "enabled", "true"),
				),
			},
			// Step 2: Add tags to FIM rule
			{
				Config: fmt.Sprintf("%s\n%s",
					testAccBasicFileRuleWithTags(testRuleName, testRuleTitle, testRuleDesc, testRuleSeverity),
					testAccThreatstackRuleTestRuleset(),
				),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRuleExists("threatstack_file_rule.test"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "name", testRuleName),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "title", testRuleTitle),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "description", testRuleDesc),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "severity", strconv.Itoa(testRuleSeverity)),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.#", "2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.3795442318", "command"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.1592629399", "filename"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "monitor_events.2605756593", "all"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.#", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.path", "/etc"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.recursive", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "filter", `event_type = "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "window", "86400"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "threshold", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.#", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.3891228369", `event_type != "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "enabled", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.source", "ec2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.key", "includekey"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.value", "includevalue"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.source", "ec2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.key", "excludekey"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.value", "excludevalue"),
				),
			},
			// Step 3: Add additional file path and suppression to FIM rule
			{
				Config: fmt.Sprintf("%s\n%s",
					testAccBasicFileRuleUpdated(testRuleName, testRuleTitle, testRuleDesc, testRuleSeverity),
					testAccThreatstackRuleTestRuleset(),
				),
				Check: resource.ComposeTestCheckFunc(
					testAccCheckThreatstackRuleExists("threatstack_file_rule.test"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "name", testRuleName),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "title", testRuleTitle),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "description", testRuleDesc),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "severity", strconv.Itoa(testRuleSeverity)),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.#", "2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.3795442318", "command"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "aggregate_fields.1592629399", "filename"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "monitor_events.2605756593", "all"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.#", "2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.path", "/etc"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1532175325.recursive", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1204901538.path", "/var/log"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "file_path.1204901538.recursive", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "filter", `event_type = "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "window", "86400"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "threshold", "1"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.#", "2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.3891228369", `event_type != "file"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "suppressions.1168292683", `command = "sudo"`),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "enabled", "true"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.source", "ec2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.key", "includekey"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "include_tag.535377537.value", "includevalue"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.source", "ec2"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.key", "excludekey"),
					resource.TestCheckResourceAttr("threatstack_file_rule.test", "exclude_tag.4230772610.value", "excludevalue"),
				),
			},
		},
	})
}

func testAccBasicFileRule(name, title, desc string, severity int) string {
	return fmt.Sprintf(`
resource "threatstack_file_rule" "test" {
	name = "%s"
	title = "%s"
	description = "%s"
	ruleset = threatstack_ruleset.test.id
	severity = %d
	### Important note - Threat Stack will force "command" and "filename" no matter what
	aggregate_fields = ["command", "filename"]
	monitor_events = ["all"]
	file_path {
		path = "/etc"
		recursive = true
	}
	filter = "event_type = \"file\""
	window = 86400
	threshold = 1
	suppressions = [
		"event_type != \"file\""
	]
	enabled = true
}
`, name, title, desc, severity)
}

func testAccBasicFileRuleWithTags(name, title, desc string, severity int) string {
	return fmt.Sprintf(`
resource "threatstack_file_rule" "test" {
	name = "%s"
	title = "%s"
	description = "%s"
	ruleset = threatstack_ruleset.test.id
	severity = %d
	### Important note - Threat Stack will force "command" and "filename" no matter what
	aggregate_fields = ["command", "filename"]
	monitor_events = ["all"]
	file_path {
		path = "/etc"
		recursive = true
	}
	filter = "event_type = \"file\""
	window = 86400
	threshold = 1
	suppressions = [
		"event_type != \"file\""
	]
	enabled = true
	### Important note: These tag keys/values must already exist in AWS.
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
`, name, title, desc, severity)
}

func testAccBasicFileRuleUpdated(name, title, desc string, severity int) string {
	return fmt.Sprintf(`
resource "threatstack_file_rule" "test" {
	name = "%s"
	title = "%s"
	description = "%s"
	ruleset = threatstack_ruleset.test.id
	severity = %d
	### Important note - Threat Stack will force "command" and "filename" no matter what
	aggregate_fields = ["command""]
	monitor_events = ["all"]
	file_path {
		path = "/etc"
		recursive = true
	}
	file_path {
		path = "/var/log"
		recursive = true
	}
	filter = "event_type = \"file\""
	window = 86400
	threshold = 1
	suppressions = [
		"event_type != \"file\"",
		"command = \"sudo\""
	]
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
`, name, title, desc, severity)
}
