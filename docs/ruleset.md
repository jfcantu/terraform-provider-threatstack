# resource `threatstack_ruleset`

A Ruleset contains Rules.

## Example Usage

```hcl
resource "threatstack_ruleset" "ruleset" {
    name = "Threat Stack Ruleset"
    description = "Example ruleset."
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the ruleset.
* `description` - (Required) A description of the ruleset.

In addition to the above arguments, the following attributes are exported:

* `id` - The ID of the ruleset.

## Import

`threatstack_ruleset` can be imported by using the ruleset ID:

```console
terraform import 00000000-0000-0000-0000-000000000000
```
