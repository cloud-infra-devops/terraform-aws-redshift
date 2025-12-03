output "cluster_id" {
  description = "Redshift cluster identifier"
  value       = aws_redshift_cluster.this[0].cluster_identifier
}

output "cluster_subnet_group_name" {
  description = "Redshift cluster subnet group name"
  value       = aws_redshift_cluster.this[0].cluster_subnet_group_name
}

output "endpoint" {
  description = "Redshift endpoint address"
  value       = aws_redshift_cluster.this[0].endpoint
}

output "port" {
  description = "Redshift port"
  value       = aws_redshift_cluster.this[0].port
}

output "secret_arn" {
  description = "ARN of the Secrets Manager secret that stores master credentials"
  value       = aws_secretsmanager_secret.redshift_master.arn
}

output "iam_role_arn" {
  description = "IAM role ARN attached to the Redshift cluster"
  value       = aws_iam_role.redshift_role.arn
}

output "kms_key_id" {
  description = "KMS key id/arn used for encryption (if created or provided)"
  value       = local.effective_kms_key_id
}

# output "secret_initial_version_id" {
#   description = "Initial Secrets Manager secret version id (username/password/dbname)"
#   value       = aws_secretsmanager_secret_version.redshift_master_version_post_cluster_creation.version_id
#   sensitive   = true
# }

output "secret_post_cluster_version_id" {
  description = "Secrets Manager secret version id that includes endpoint and port (created after cluster)"
  value       = aws_secretsmanager_secret_version.redshift_master_version_post_cluster_creation.version_id
  sensitive   = true
}
