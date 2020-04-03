module github.com/jfcantu/terraform-provider-threatstack

go 1.14

require (
	github.com/hashicorp/terraform v0.12.23
	github.com/hashicorp/terraform-plugin-sdk v1.8.0
	github.com/jfcantu/threatstack-golang v0.1.3
	github.com/sirupsen/logrus v1.4.2
)

replace github.com/jfcantu/threatstack-golang => ../threatstack-golang

replace github.com/jfcantu/terraform-provider-threatstack => ./
