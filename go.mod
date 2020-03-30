module github.com/jfcantu/terraform-provider-threatstack

go 1.13

require (
	github.com/hashicorp/terraform v0.12.23
	github.com/hashicorp/terraform-plugin-sdk v1.8.0
	github.com/jfcantu/threatstack-golang/threatstack v0.0.0-00010101000000-000000000000
	github.com/sirupsen/logrus v1.4.2
)

replace github.com/jfcantu/threatstack-golang/threatstack => ../threatstack-golang/threatstack

replace github.com/jfcantu/terraform-provider-threatstack => ./
