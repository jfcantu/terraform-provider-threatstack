package main

import (
	"fmt"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-sdk/helper/resource"
	"github.com/jfcantu/threatstack-golang/threatstack"
)

func TestMain(m *testing.M) {
	resource.TestMain(m)
}

func sharedClient() (*threatstack.Client, error) {
	var authData map[string]string

	for _, v := range []string{"THREATSTACK_API_KEY", "THREATSTACK_USER_ID", "THREATSTACK_ORG_ID"} {
		if authData[v] = os.Getenv(v); authData[v] == "" {
			return nil, fmt.Errorf("Required environment variable %v not set", v)
		}
	}

	cli, err := threatstack.NewClient(&threatstack.Config{
		APIKey:         authData["THREATSTACK_API_KEY"],
		OrganizationID: authData["THREATSTACK_ORG_ID"],
		UserID:         authData["THREATSTACK_USER_ID"],
	})
	if err != nil {
		return nil, err
	}

	return cli, nil
}
