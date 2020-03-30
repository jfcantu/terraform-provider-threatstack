package main

import (
	"fmt"
	"math/rand"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/terraform"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/jfcantu/threatstack-golang/threatstack"
)

type testRuleData struct {
	Name            string
	Title           string
	Description     string
	Type            string
	Severity        int
	AggregateFields []string
	Filter          string
	Window          int
	Threshold       int
	Suppressions    []string
	Enabled         bool
}

func initializeTestRuleData() *testRuleData {
	d := new(testRuleData)
	d.Name = acctest.RandomWithPrefix("tf")
	d.Title = acctest.RandomWithPrefix("tf")
	d.Description = acctest.RandomWithPrefix("tf")
	d.Severity = (rand.Intn(3-1) + 1)
	d.Filter = acctest.RandomWithPrefix("tf")
	d.Window = getValidRuleWindows()[rand.Intn(len(getValidRuleWindows()))]
	d.Threshold = getValidRuleThresholds()[rand.Intn(len(getValidRuleThresholds()))]

	return d
}

func testAccCheckThreatstackRuleExists(name string) resource.TestCheckFunc {
	return func(s *terraform.State) error {

		cli := testAccProvider.Meta().(*threatstack.Client)

		res, ok := s.RootModule().Resources[name]
		if !ok {
			return fmt.Errorf("Not found: %s", name)
		}

		if res.Primary.ID == "" {
			return fmt.Errorf("No ID is set")
		}

		if _, err := cli.Rules.Get(res.Primary.Attributes["ruleset"], res.Primary.ID); err != nil {
			return fmt.Errorf("Error retrieving rule: %s", err.Error())
		}

		return nil
	}
}

func testAccCheckThreatstackRuleDestroyed(s *terraform.State) error {
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
