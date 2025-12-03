# provider "aws" {
#   # configured by caller
# }
data "aws_caller_identity" "current" {}

locals {
  master_password          = var.master_password != "" ? var.master_password : (length(random_password.master) > 0 ? random_password.master[0].result : "")
  kms_key_exists           = var.kms_key_id != ""
  kms_key_alias            = "alias/terraform-redshift-${replace(var.cluster_identifier, "/", "-")}"
  effective_logging_bucket = var.logging_s3_bucket_name != "" ? var.logging_s3_bucket_name : (var.create_log_bucket ? aws_s3_bucket.redshift_logs[0].bucket : "")
  effective_kms_key_id     = var.kms_key_id != "" ? var.kms_key_id : (length(aws_kms_key.redshift_kms_key) > 0 ? aws_kms_key.redshift_kms_key[0].arn : "")
}

resource "random_password" "master" {
  count   = var.master_password == "" ? 1 : 0
  length  = var.pwd_length
  special = true
  keepers = {
    cluster = var.cluster_identifier
  }
  lifecycle {
    prevent_destroy = false
  }
}

# Optional created KMS key
resource "aws_kms_key" "redshift_kms_key" {
  count                   = var.create_kms_key && !local.kms_key_exists ? 1 : 0
  description             = "KMS key for Redshift cluster ${var.cluster_identifier}"
  deletion_window_in_days = var.kms_key_deletion_window_in_days

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "Allow principals in account full access to key"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      }
      # allow Redshift service to use the key
      , {
        Sid       = "AllowRedshiftServiceUse"
        Effect    = "Allow"
        Principal = { Service = "redshift.amazonaws.com" }
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = ["arn:aws:redshift:*:${data.aws_caller_identity.current.account_id}:cluster:${var.cluster_identifier}"]
      }
    ]
  })
}

resource "aws_kms_alias" "redshift_alias" {
  count         = length(aws_kms_key.redshift_kms_key) > 0 ? 1 : 0
  name          = local.kms_key_alias
  target_key_id = aws_kms_key.redshift_kms_key[0].id
}

# S3 bucket for logs (optional creation)
resource "aws_s3_bucket" "redshift_logs" {
  count  = var.create_log_bucket && var.logging_s3_bucket_name == "" ? 1 : 0
  bucket = "${replace(var.cluster_identifier, "/", "-")}-redshift-logs-${data.aws_caller_identity.current.account_id}"

  tags = merge({ Name = "${var.cluster_identifier}-redshift-logs" }, var.tags)
}

resource "aws_s3_bucket_server_side_encryption_configuration" "redshift_logs" {
  count  = var.create_log_bucket && var.logging_s3_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.redshift_logs[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_id != "" ? var.kms_key_id : (length(aws_kms_key.redshift_kms_key) > 0 ? aws_kms_key.redshift_kms_key[0].arn : null)
    }
  }
}

resource "aws_s3_bucket_acl" "redshift_logs" {
  count  = var.create_log_bucket && var.logging_s3_bucket_name == "" ? 1 : 0
  bucket = aws_s3_bucket.redshift_logs[0].id
  acl    = "private"
}

# Create a Redshift subnet group optionally using provided subnet_ids & vpc_id
resource "aws_redshift_subnet_group" "this" {
  count       = var.create_subnet_group ? 1 : 0
  name        = "${var.cluster_identifier}-subnet-group"
  description = "Redshift subnet group for ${var.cluster_identifier}"
  subnet_ids  = var.subnet_ids

  tags = merge(
    {
      Name = "${var.cluster_identifier}-subnet-group"
    },
    var.tags,
    (var.vpc_id != "" ? { "vpc-id" = var.vpc_id } : {})
  )
}

# Determine the subnet group name used by the cluster
locals {
  redshift_subnet_group_name = var.create_subnet_group ? aws_redshift_subnet_group.this[0].name : var.subnet_group_name
}

# Secrets Manager secret with master credentials
resource "aws_secretsmanager_secret" "redshift_master" {
  name        = "${var.cluster_identifier}-redshift-master-credentials"
  description = "Redshift master credentials for cluster ${var.cluster_identifier}"
  kms_key_id  = local.effective_kms_key_id != "" ? local.effective_kms_key_id : null
  tags        = merge({ Name = "${var.cluster_identifier}-redshift-secret" }, var.tags)
}

# resource "aws_secretsmanager_secret_version" "redshift_master_version" {
#   depends_on = [aws_secretsmanager_secret.redshift_master]
#   secret_id  = aws_secretsmanager_secret.redshift_master.id
#   secret_string = jsonencode({
#     username = var.master_username
#     password = local.master_password
#     dbname   = var.db_name
#   })
# }

# IAM role for Redshift
resource "aws_iam_role" "redshift_role" {
  name = "${var.cluster_identifier}-redshift-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "redshift.amazonaws.com"
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
  tags = var.tags
}

# Attach AWS-managed full Redshift policy
resource "aws_iam_role_policy_attachment" "redshift_full_access" {
  role       = aws_iam_role.redshift_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonRedshiftFullAccess"
}

# Inline policy: allow reading specific secret and secretsmanager operations and kms decrypt (if kms key is used)
data "aws_iam_policy_document" "secrets_access" {
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetSecretValue",
      "secretsmanager:DescribeSecret",
      "secretsmanager:ListSecretVersionIds",
      "secretsmanager:ListSecrets"
    ]
    resources = [
      aws_secretsmanager_secret.redshift_master.arn,
      "${aws_secretsmanager_secret.redshift_master.arn}/*"
    ]
  }

  # Allow reading the secret's resource policy (optional)
  statement {
    effect = "Allow"
    actions = [
      "secretsmanager:GetResourcePolicy"
    ]
    resources = [aws_secretsmanager_secret.redshift_master.arn]
  }

  dynamic "statement" {
    for_each = local.effective_kms_key_id != "" ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "kms:Decrypt",
        "kms:Encrypt",
        "kms:GenerateDataKey*",
        "kms:DescribeKey"
      ]
      resources = [local.effective_kms_key_id]
    }
  }
}

resource "aws_iam_role_policy" "redshift_secrets_policy" {
  name   = "${var.cluster_identifier}-redshift-secrets"
  role   = aws_iam_role.redshift_role.id
  policy = data.aws_iam_policy_document.secrets_access.json
}

# Create a security group for Redshift (optional)
resource "aws_security_group" "redshift" {
  count       = var.create_security_group ? 1 : 0
  name        = var.security_group_name != "" ? var.security_group_name : "${var.cluster_identifier}-sg"
  description = var.security_group_description
  vpc_id      = var.vpc_id != "" ? var.vpc_id : null

  tags = merge(
    {
      Name = "${var.cluster_identifier}-sg"
    },
    var.tags
  )
}

# Ingress rules for created SG
resource "aws_security_group_rule" "ingress" {
  for_each          = var.create_security_group ? { for idx, r in var.security_group_ingress : idx => r } : {}
  description       = lookup(each.value, "description", null)
  type              = "ingress"
  from_port         = each.value.from_port
  to_port           = each.value.to_port
  protocol          = each.value.protocol
  cidr_blocks       = each.value.cidr_blocks
  security_group_id = aws_security_group.redshift[0].id
}

# Egress rules for created SG (if none provided, allow all outbound)
resource "aws_security_group_rule" "egress" {
  count = var.create_security_group ? (length(var.security_group_egress) > 0 ? length(var.security_group_egress) : 1) : 0

  security_group_id = aws_security_group.redshift[0].id
  type              = "egress"
  description       = length(var.security_group_egress) > 0 ? lookup(var.security_group_egress[count.index], "description", null) : "Allow all outbound"
  from_port         = length(var.security_group_egress) > 0 ? var.security_group_egress[count.index].from_port : 0
  to_port           = length(var.security_group_egress) > 0 ? var.security_group_egress[count.index].to_port : 0
  protocol          = length(var.security_group_egress) > 0 ? var.security_group_egress[count.index].protocol : "-1"
  cidr_blocks       = length(var.security_group_egress) > 0 ? var.security_group_egress[count.index].cidr_blocks : ["0.0.0.0/0"]
}

# Effective security group ids used by the cluster: caller-provided ones plus created SG (if any)
locals {
  redshift_vpc_security_group_ids = concat(
    var.vpc_security_group_ids,
    var.create_security_group ? [aws_security_group.redshift[0].id] : []
  )
}

# Redshift cluster
resource "aws_redshift_cluster" "this" {
  depends_on                          = [aws_iam_role_policy_attachment.redshift_full_access]
  count                               = var.create_redshift_cluster ? 1 : 0
  cluster_identifier                  = var.cluster_identifier
  database_name                       = var.db_name
  master_username                     = var.master_username
  master_password                     = local.master_password
  node_type                           = var.node_type
  cluster_type                        = var.cluster_type
  publicly_accessible                 = var.redshift_accessibility_type
  number_of_nodes                     = var.cluster_type == "multi-node" ? var.number_of_nodes : null
  cluster_subnet_group_name           = local.redshift_subnet_group_name
  vpc_security_group_ids              = local.redshift_vpc_security_group_ids
  iam_roles                           = [aws_iam_role.redshift_role.arn]
  encrypted                           = true
  kms_key_id                          = local.effective_kms_key_id != "" ? local.effective_kms_key_id : null
  preferred_maintenance_window        = var.preferred_maintenance_window != "" ? var.preferred_maintenance_window : null
  automated_snapshot_retention_period = var.automated_snapshot_retention_period
  allow_version_upgrade               = true
  enhanced_vpc_routing                = var.enhanced_vpc_routing
  tags                                = var.tags
  lifecycle {
    ignore_changes = [
      # master_password rotations are done via secrets manager; prevent accidental re-creation from password rotation
      master_password
    ]
  }
}

# Post-cluster secret version: add endpoint/port/jdbc after cluster creation
resource "aws_secretsmanager_secret_version" "redshift_master_version_post_cluster" {
  # ensure cluster is created first so endpoint/port are available
  depends_on = [aws_redshift_cluster.this]
  secret_id  = aws_secretsmanager_secret.redshift_master.id

  secret_string = jsonencode({
    username           = var.master_username
    password           = local.master_password
    dbname             = var.db_name
    endpoint           = aws_redshift_cluster.this.endpoint
    port               = aws_redshift_cluster.this.port
    jdbc               = "jdbc:redshift://${aws_redshift_cluster.this.endpoint}:${aws_redshift_cluster.this.port}/${var.db_name}"
    cluster_identifier = var.cluster_identifier
  })
}

# Basic CloudWatch alarm (optional)
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  depends_on = [aws_redshift_cluster.this]
  count      = var.create_monitoring_alarm ? 1 : 0

  alarm_name          = "${var.cluster_identifier}-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/Redshift"
  period              = 300
  statistic           = "Average"
  threshold           = var.cpu_alarm_threshold
  alarm_description   = "Alarm when Redshift CPU is > ${var.cpu_alarm_threshold}%"

  dimensions = {
    ClusterIdentifier = var.cluster_identifier
  }

  treat_missing_data        = "missing"
  alarm_actions             = [] # leave empty for caller to provide SNS topic ARNs via separate resource or by modifying this module
  ok_actions                = []
  insufficient_data_actions = []
}

