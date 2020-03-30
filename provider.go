package main

import (
	"log"

	"github.com/jfcantu/threatstack-golang/threatstack"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

// Provider - as required
func Provider() *schema.Provider {
	p := &schema.Provider{
		Schema: map[string]*schema.Schema{
			"api_key": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Threat Stack API key.",
				DefaultFunc: schema.EnvDefaultFunc("THREATSTACK_API_KEY", nil),
			},
			"organization_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Threat Stack organization ID.",
				DefaultFunc: schema.EnvDefaultFunc("THREATSTACK_ORG_ID", nil),
			},
			"user_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Threat Stack user ID.",
				DefaultFunc: schema.EnvDefaultFunc("THREATSTACK_USER_ID", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"threatstack_ruleset":   resourceRuleset(),
			"threatstack_host_rule": resourceHostRule(),
			"threatstack_file_rule": resourceFileRule(),
		},
	}

	p.ConfigureFunc = func(d *schema.ResourceData) (interface{}, error) {
		return providerConfigure(d)
	}

	return p
}

func providerConfigure(data *schema.ResourceData) (interface{}, error) {
	config := Config{
		APIKey:         data.Get("api_key").(string),
		OrganizationID: data.Get("organization_id").(string),
		UserID:         data.Get("user_id").(string),
	}

	log.Println("[INFO] Initializing Threat Stack client")
	return config.Client()
}

// Client creates a new client.
func (cfg *Config) Client() (*threatstack.Client, error) {
	tsconfig := &threatstack.Config{
		BaseURL:        "https://api.threatstack.com",
		APIKey:         cfg.APIKey,
		OrganizationID: cfg.OrganizationID,
		UserID:         cfg.UserID,
	}

	log.Printf("[INFO] Creating Threat Stack client")

	client, err := threatstack.NewClient(tsconfig)
	if err != nil {
		return nil, err
	}

	return client, err
}
