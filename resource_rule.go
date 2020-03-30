package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
)

func validateRuleWindow() schema.SchemaValidateFunc {
	return validation.IntInSlice(getValidRuleWindows())
}

func getValidRuleWindows() []int {
	return []int{
		3600,
		7200,
		14400,
		28800,
		57600,
		86400,
	}
}

func getValidRuleThresholds() []int {
	return []int{
		1,
		5,
		10,
		20,
		40,
		60,
	}
}
