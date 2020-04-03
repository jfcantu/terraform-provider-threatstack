package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/jfcantu/threatstack-golang/threatstack"
)

func resourceRuleset() *schema.Resource {
	return &schema.Resource{
		Create: resourceRulesetCreate,
		Read:   resourceRulesetRead,
		Update: resourceRulesetUpdate,
		Delete: resourceRulesetDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func resourceRulesetCreate(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	name := resourceData.Get("name").(string)
	desc := resourceData.Get("description").(string)

	ruleset, err := client.Rulesets.Create(
		&threatstack.Ruleset{
			Name:        name,
			Description: desc,
			RuleIDs:     []string{},
		})
	if err != nil {
		return err
	}

	resourceData.SetId(ruleset.ID)
	return resourceRulesetRead(resourceData, meta)
}

func resourceRulesetRead(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	data, err := client.Rulesets.Get(resourceData.Id())
	if err != nil {
		return nil
	}

	resourceData.Set("name", data.Name)
	resourceData.Set("description", data.Description)

	return nil
}

func resourceRulesetUpdate(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	id := resourceData.Id()
	name := resourceData.Get("name").(string)
	desc := resourceData.Get("description").(string)

	current, err := client.Rulesets.Get(id)
	if err != nil {
		return err
	}

	_, err = client.Rulesets.Update(
		&threatstack.Ruleset{
			ID:          id,
			Name:        name,
			Description: desc,
			RuleIDs:     current.RuleIDs,
		})
	if err != nil {
		return nil
	}

	return resourceRulesetRead(resourceData, meta)
}

func resourceRulesetDelete(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	id := resourceData.Id()

	err := client.Rulesets.Delete(id)
	if err != nil {
		return nil
	}

	return nil
}
