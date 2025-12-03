```markdown
# Terraform module: redshift-cluster

Creates:
- (optional) KMS key for encryption
- Secrets Manager secret storing the Redshift master credentials
- IAM role for Redshift with AmazonRedshiftFullAccess and an inline policy allowing reading the secret and using the KMS key
- An encrypted Redshift cluster in an existing subnet group and with existing security groups
- Optional S3 bucket for audit logging
- Optional CloudWatch alarm for high CPU utilization

Usage:
```hcl
module "redshift" {
  source = "../modules/redshift-cluster"

  cluster_identifier = "my-redshift-cluster"
  subnet_group_name  = "existing-redshift-subnet-group"
  vpc_security_group_ids = ["sg-0123456789abcdef0"]
  db_name = "analytics"
  master_username = "admin"

  # let module create KMS key (default) or pass your own
  create_kms_key = true
  # kms_key_id = "arn:aws:kms:region:acct:key/... (optional)"

  # logging
  enable_logging = true
  create_log_bucket = false
  logging_s3_bucket_name = "my-existing-redshift-logs"

  # monitoring
  create_monitoring_alarm = true

  tags = {
    Environment = "prod"
    Project     = "analytics"
  }
}
```
S3 server-side encryption deprecation fix
- The AWS provider deprecated the inline `server_side_encryption_configuration` nested block under `aws_s3_bucket`.
- This module now uses the dedicated `aws_s3_bucket_server_side_encryption_configuration` resource to configure SSE.
- If you provide a KMS key (`kms_key_id`), the module configures SSE with `aws:kms` and sets the KMS key on the bucket.
- If no KMS key is provided and the module creates the bucket, it configures AES256 SSE.
- The module avoids bucket ACL calls by default; set `allow_bucket_acl = true` only if your account/bucket supports ACLs.
  
Notes:
- The module creates a Secrets Manager secret before cluster creation that contains the master username and password. The password is randomly generated if you do not pass master_password.
- The IAM role created is assumable by Redshift and has the AWS managed policy `AmazonRedshiftFullAccess`. The module also attaches a policy allowing that role to call `secretsmanager:GetSecretValue` and key usage on the KMS key, so the cluster can access the secret if you use the role in your Redshift workflows.
- After creation, you may want to update the secret to include the cluster endpoint and port (the module currently stores username/password/dbname).
```
