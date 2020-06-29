# resource `threatstack_file_rule`

A File Rule contains a Threat Stack rule for monitoring FIM events.

## Example Usage

```hcl
resource "threatstack_file_rule" "rule" {
    name = "File: Secret File Opens"
    title = "File: Secret File Opens: {{command}} on {{filename}} with {{arguments}}"
    description = "This rule alerts on OPEN events on secret files, which might have customer data, access keys, or secret configuration data."

    ruleset = threatstack_ruleset.ruleset.id

    aggregate_fields = ["command", "filename", "arguments"]

    threshold = 1
    window = 86400

    severity = 3

    filter = "user != \"ts-user\""

    file_path {
        path = "/home/ubuntu/.aws"
    }

    ignore_files = [
        "*swp",
        "*swpx",
        "*lock",
        "*tmp",
        "*pkg",
        "*dpkg-new",
        "nssdb*",
        ".*",
        "*~",
        "*+",
        "*-"
    ]

    monitor_events = ["open"]

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
* `ignore_files` - (Optional) File patterns to ignore.
* `monitor_events` - (Required) File events to alert on.

You must specify at least one `file_path` block denoting what file paths should be monitored. The `file_path` block contains the following arguments:

* `path` - (Required) File path to monitor.
* `recursive` - (Optional) Monitor subdirectories recursively. (Defaults to `false`.)

You may also specify multiple `include_tag` and `exclude_tag` blocks to indicate host tags that should be included/excluded from alerting.

**Note**: The tags must already exist within Threat Stack.

The `include_tag` and `exclude_tag` blocks must contain the following attributes:

* `source` - The source of the tag.
* `key` - The tag key to be matched.
* `key` - The tag value to be matched.

## Import

`threatstack_file_rule` can be imported by using the ruleset ID, and underscore, and the rule ID:

```console
terraform import 00000000-0000-0000-0000-000000000000_11111111-1111-1111-1111-111111111111
```
