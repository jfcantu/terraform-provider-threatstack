package main

import (
	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/helper/validation"
	"github.com/jfcantu/threatstack-golang/threatstack"
)

func resourceHostRule() *schema.Resource {
	return &schema.Resource{
		Create: resourceHostRuleCreate,
		Read:   resourceHostRuleRead,
		Update: resourceHostRuleUpdate,
		Delete: resourceHostRuleDelete,

		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"include_tag": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"source": {
							Type:     schema.TypeString,
							Required: true,
						},
						"key": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"exclude_tag": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"source": {
							Type:     schema.TypeString,
							Required: true,
						},
						"key": {
							Type:     schema.TypeString,
							Required: true,
						},
						"value": {
							Type:     schema.TypeString,
							Required: true,
						},
					},
				},
			},
			"title": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"description": &schema.Schema{
				Type:     schema.TypeString,
				Optional: true,
			},
			"ruleset": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"severity": &schema.Schema{
				Type:     schema.TypeInt,
				Required: true,
			},
			"aggregate_fields": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"filter": &schema.Schema{
				Type:     schema.TypeString,
				Required: true,
			},
			"window": &schema.Schema{
				Type:     schema.TypeInt,
				Required: true,
			},
			"threshold": &schema.Schema{
				Type:     schema.TypeInt,
				Required: true,
			},
			"suppressions": &schema.Schema{
				Type:     schema.TypeSet,
				Optional: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"enabled": &schema.Schema{
				Type:     schema.TypeBool,
				Optional: true,
				Default:  true,
			},
		},
	}
}

func resourceHostRuleCreate(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	name := resourceData.Get("name").(string)
	title := resourceData.Get("title").(string)
	desc := resourceData.Get("description").(string)
	ruleset := resourceData.Get("ruleset").(string)
	severity := resourceData.Get("severity").(int)

	var aggregate []string
	for _, v := range resourceData.Get("aggregate_fields").(*schema.Set).List() {
		aggregate = append(aggregate, v.(string))
	}

	filter := resourceData.Get("filter").(string)
	window := resourceData.Get("window").(int)
	threshold := resourceData.Get("threshold").(int)

	var suppressions []string
	for _, v := range resourceData.Get("suppressions").(*schema.Set).List() {
		suppressions = append(suppressions, v.(string))
	}
	enabled := resourceData.Get("enabled").(bool)
	tags := threatstack.NewTagSet()

	for _, tag := range resourceData.Get("include_tag").(*schema.Set).List() {
		tags.Include = append(tags.Include, &threatstack.Tag{
			Source: tag.(map[string]interface{})["source"].(string),
			Key:    tag.(map[string]interface{})["key"].(string),
			Value:  tag.(map[string]interface{})["value"].(string),
		})
	}
	for _, tag := range resourceData.Get("exclude_tag").(*schema.Set).List() {
		tags.Exclude = append(tags.Exclude, &threatstack.Tag{
			Source: tag.(map[string]interface{})["source"].(string),
			Key:    tag.(map[string]interface{})["key"].(string),
			Value:  tag.(map[string]interface{})["value"].(string),
		})
	}

	rule, err := client.Rules.Create(
		ruleset,
		&threatstack.HostRule{
			Type:            "Host",
			Name:            name,
			Tags:            tags,
			Title:           title,
			Description:     desc,
			Severity:        severity,
			AggregateFields: aggregate,
			Filter:          filter,
			Window:          window,
			Threshold:       threshold,
			Suppressions:    suppressions,
			Enabled:         enabled,
		})
	if err != nil {
		return err
	}

	resourceData.SetId((*rule).GetID())
	return resourceHostRuleRead(resourceData, meta)
}

func resourceHostRuleRead(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	ruleset := resourceData.Get("ruleset").(string)
	id := resourceData.Id()

	resp, err := client.Rules.Get(ruleset, id)
	if err != nil {
		return nil
	}

	resourceData.Set("name", (*resp).(*threatstack.HostRule).Name)
	resourceData.Set("type", (*resp).(*threatstack.HostRule).Type)
	resourceData.Set("title", (*resp).(*threatstack.HostRule).Title)
	resourceData.Set("severity", (*resp).(*threatstack.HostRule).Severity)
	resourceData.Set("filter", (*resp).(*threatstack.HostRule).Filter)
	resourceData.Set("window", (*resp).(*threatstack.HostRule).Window)
	resourceData.Set("threshold", (*resp).(*threatstack.HostRule).Threshold)
	resourceData.Set("enabled", (*resp).(*threatstack.HostRule).Enabled)

	return nil
}

func resourceHostRuleUpdate(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	id := resourceData.Id()
	name := resourceData.Get("name").(string)
	title := resourceData.Get("title").(string)
	desc := resourceData.Get("description").(string)
	ruleset := resourceData.Get("ruleset").(string)
	severity := resourceData.Get("severity").(int)
	aggregate := resourceData.Get("aggregate_fields").([]string)
	filter := resourceData.Get("filter").(string)
	window := resourceData.Get("window").(int)
	threshold := resourceData.Get("threshold").(int)
	suppressions := resourceData.Get("suppressions").([]string)
	enabled := resourceData.Get("enabled").(bool)

	_, err := client.Rules.Update(
		ruleset,
		id,
		&threatstack.HostRule{
			Type:            "Host",
			Name:            name,
			Title:           title,
			Description:     desc,
			RulesetID:       ruleset,
			Severity:        severity,
			AggregateFields: aggregate,
			Filter:          filter,
			Window:          window,
			Threshold:       threshold,
			Suppressions:    suppressions,
			Enabled:         enabled,
		})
	if err != nil {
		return nil
	}

	return resourceHostRuleRead(resourceData, meta)
}

func resourceHostRuleDelete(resourceData *schema.ResourceData, meta interface{}) error {
	client := meta.(*threatstack.Client)

	id := resourceData.Id()
	ruleset := resourceData.Get("ruleset").(string)

	err := client.Rules.Delete(ruleset, id)
	if err != nil {
		return nil
	}

	return nil
}

func validateHostRuleAggregateFields() schema.SchemaValidateFunc {
	return validation.StringInSlice(getValidHostRuleAggregateFields(), true)
}

func getValidHostRuleAggregateFields() []string {
	return []string{
		"exe",
		"user",
		"arguments",
		"ip",
		"port",
		"command",
		"session",
		"src_ip",
		"dst_ip",
		"src_user",
		"dst_user",
		"filename",
	}
}
