# Terraform

Terraform is used for managing the OONI infrastructure as code.

## Quickstart

1. Install [terraform](https://developer.hashicorp.com/terraform/install)
2. Setup AWS credentials by making your ~/.aws/credentials look like this:

```
[oonidevops_user]
aws_access_key_id = YYYY
aws_secret_access_key = ZZZ
region = eu-central-1
[oonidevops_user_dev]
role_arn = arn:aws:iam::905418398257:role/oonidevops
source_profile = oonidevops_user
region = eu-central-1
[oonidevops_user_prod]
role_arn = arn:aws:iam::471112720364:role/oonidevops
source_profile = oonidevops_user
region = eu-central-1
```

Where you replace OONI_ORG_ID with the ID of the ORG you are deploying to (dev,
test or prod).

3. Run `terrafrom plan` to check the plan
4. Run `terraform apply` to apply the plan

Once you have applied a plan the changes to the terraform config should be
pushed to the `main` branch immediately so that we minimize the change of other
people applying stale configurations.

### FEI (Frequently Encountered Issues)

#### What to do if you get a locked state

```
% terraform plan
╷
│ Error: Error acquiring the state lock
│
│ Error message: operation error DynamoDB: PutItem, https response error StatusCode: 400, RequestID:
│ IBL35BESTVD1GQID3TRON01ADFVV4KQNSO5AEMVJF66Q9ASUAAJG, ConditionalCheckFailedException: The conditional request failed
│ Lock Info:
│   ID:        7622a128-79f1-2179-815a-d821369a815e
│   Path:      ooni-production-terraform-state/terraform.tfstate
│   Operation: OperationTypeApply
│   Who:       art@himiko.local
│   Version:   1.7.0
│   Created:   2024-02-05 11:51:45.398054 +0000 UTC
│   Info:
│
│
│ Terraform acquires a state lock to protect the state from being written
│ by multiple users at the same time. Please resolve the issue above and try
│ again. For most commands, you can disable locking with the "-lock=false"
│ flag, but this is not recommended.
```

```
% terraform force-unlock -force 7622a128-79f1-2179-815a-d821369a815e
Terraform state has been successfully unlocked!

The state has been unlocked, and Terraform commands should now be able to
obtain a new lock on the remote state.
```

### Notes

https://www.terraform-best-practices.com/naming

Sometimes it's useful to specify a target like this:

```
terraform apply -target=module.ooniapi_frontend.aws_lb_listener_rule.oonidataapi_rule
```
