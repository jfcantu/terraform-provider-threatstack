# resource `threatstack_host_rule`

A Host Rule contains a Threat Stack rule for monitoring host events.

## Example Usage

```hcl
resource "threatstack_host_rule" "rule" {
    name = "Host: New User Added"
    title = "Host: New User Added"
    description = "This alerts when a user is added."

    ruleset = threatstack_ruleset.ruleset.id

    threshold = 1
    window = 86400

    severity = 3

    filter = "event_type = \"host\" and sigid = \"5902\""

    suppressions = [
        "user = \"chef\""
    ]

    include_tag {
        source = "ec2"
        key = "environment"
        value = "production"
    }
}

resource "threatstack_ruleset" "ruleset" {
    name = "Example ruleset"
    description = "An example ruleset.
}
```

## Argument Reference

The following arguments are supported:

* `name` - (Required) The name of the rule.
* `title` - (Required) The title of alerts that fire from this rule.
* `description` - (Optional) A description of the rule.
* `ruleset` - (Required) The ruleset ID to add the rule to.
* `severity` - (Required) The severity of alerts from this rule.
* `aggregate_fields` - (Optional) Alert fields to aggregate on.
* `filter` - (Required) Filter for matching events.
* `threshold` - (Required) Event count threshold for alerts to fire.
* `window` - (Required) Time window for event threshold.
* `suppressions` - (Optional) List of filters for events to exclude from alerting.
* `enabled` - (Optional) Enable this alert. (Defaults to `true`.)

You may also specify multiple `include_tag` and `exclude_tag` blocks to indicate host tags that should be included/excluded from alerting.

**Note**: The tags must already exist within Threat Stack.

The `include_tag` and `exclude_tag` blocks must contain the following attributes:

* `source` - The source of the tag.
* `key` - The tag key to be matched.
* `key` - The tag value to be matched.

## Import

`threatstack_host_rule` can be imported by using the ruleset ID, and underscore, and the rule ID:

```console
terraform import 00000000-0000-0000-0000-000000000000_11111111-1111-1111-1111-111111111111
```
