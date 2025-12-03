variable "create_redshift_cluster" {
  description = "create redshift cluster or not"
  type        = bool
  default     = true
}

variable "cluster_identifier" {
  description = "Redshift cluster identifier"
  type        = string
}

variable "node_type" {
  description = "Redshift node type"
  type        = string
  default     = "dc2.large"
}

variable "cluster_type" {
  description = "single-node or multi-node"
  type        = string
  default     = "multi-node"
}

variable "redshift_accessibility_type" {
  description = "check whether redshift cluster is publicly accessible"
  type        = bool
  default     = false
}

variable "number_of_nodes" {
  description = "Number of compute nodes (only used if cluster_type == 'multi-node')"
  type        = number
  default     = 2
}

variable "db_name" {
  description = "Initial database name"
  type        = string
  # default     = "dev"
}

variable "master_username" {
  description = "Master username for the Redshift cluster (if empty, 'admin' will be used)"
  type        = string
  default     = "admin"
}

variable "master_password" {
  description = "Master password. If not provided, a random password will be generated. Must NOT contain / @ \" ' or space."
  type        = string
  default     = ""
  sensitive   = true
  validation {
    condition     = var.master_password == "" || length(regexall("[/@\"' ]", var.master_password)) == 0
    error_message = "master_password must not contain any of these characters: / @ \" ' or space. If you don't want to provide a password, leave this blank and let the module generate one."
  }
}

variable "pwd_length" {
  description = "min length of master password"
  type        = number
  default     = 16
}

variable "vpc_id" {
  description = "The VPC ID to tag on the subnet group (optional)."
  type        = string
  default     = ""
}

variable "subnet_ids" {
  description = "List of subnet IDs for the Redshift subnet group."
  type        = list(string)
  default     = []
}

variable "create_subnet_group" {
  description = "Whether to create a Redshift subnet group"
  type        = bool
  default     = true
}

variable "subnet_group_name" {
  description = "Existing Redshift subnet group name to place the cluster into"
  type        = string
  default     = ""
}

# Optionally create a security group for the Redshift cluster
variable "create_security_group" {
  description = "Whether to create a new security group for the Redshift cluster. If true, the created SG ID will be appended to vpc_security_group_ids for the cluster."
  type        = bool
  default     = true
}

# Existing security groups (caller-provided)
variable "vpc_security_group_ids" {
  description = "List of existing VPC security group IDs for the Redshift cluster (optional). Created SG (if enabled) will be appended to this list."
  type        = list(string)
  default     = []
}

variable "security_group_name" {
  # description = "Name to give the created security group (when create_security_group = true). Defaults to ${var.cluster_identifier}-sg"
  type    = string
  default = ""
}

variable "security_group_description" {
  description = "Description for the created security group (when create_security_group = true)."
  type        = string
  default     = "Security group for Redshift cluster created by terraform module"
}

variable "security_group_ingress" {
  description = "List of ingress rules for the created security group. Each entry: { from_port = number, to_port = number, protocol = string, cidr_blocks = [\"...\"], description = string }"
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = optional(string)
  }))
  default = []
}

variable "security_group_egress" {
  description = "List of egress rules for the created security group. Same shape as ingress. If empty, a default allow-all-egress will be created."
  type = list(object({
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
    description = optional(string)
  }))
  default = []
}

variable "redshift_port" {
  description = "Port Redshift listens on (used in default ingress rules)."
  type        = number
  default     = 5439
}

variable "kms_key_id" {
  description = "Optional existing KMS key id/arn to encrypt the cluster and secret. If empty, the module may create a KMS key when create_kms_key = true."
  type        = string
  default     = ""
}

variable "create_kms_key" {
  description = "Whether to create a KMS key for encryption. If true and kms_key_id is empty, a key will be created."
  type        = bool
  default     = true
}

variable "kms_key_deletion_window_in_days" {
  description = "Number of days before the KMS key is deleted after destruction"
  type        = number
  default     = 7
}

variable "create_log_bucket" {
  description = "Whether to create an S3 bucket for Redshift audit logging. If false, provide logging_s3_bucket_name."
  type        = bool
  default     = true
}

variable "logging_s3_bucket_name" {
  description = "Existing S3 bucket name to store Redshift logs. If empty and create_log_bucket = true, a bucket will be created."
  type        = string
  default     = ""
}

variable "allow_bucket_acl" {
  description = "Whether to allow bucket ACL creation for the S3 logging bucket"
  type        = bool
  default     = false
}

variable "logging_s3_key_prefix" {
  description = "S3 key prefix for Redshift logs"
  type        = string
  default     = "redshift-logs/"
}

variable "enable_logging" {
  description = "Enable Redshift audit logging to S3"
  type        = bool
  default     = true
}

variable "preferred_maintenance_window" {
  description = "Maintenance window in the format ddd:hh:mi-ddd:hh:mi (e.g. 'sun:23:45-sun:23:55')"
  type        = string
  default     = "sun:20:45-sun:23:45"
}

variable "automated_snapshot_retention_period" {
  description = "Automated snapshot retention period (days). Set 0 to disable."
  type        = number
  default     = 1
}

variable "enhanced_vpc_routing" {
  description = "Whether to enable enhanced VPC routing"
  type        = bool
  default     = true
}

variable "create_monitoring_alarm" {
  description = "Whether to create a basic CloudWatch alarm for high CPU utilization"
  type        = bool
  default     = false
}

variable "cpu_alarm_threshold" {
  description = "CPU utilization percentage threshold for the CloudWatch alarm"
  type        = number
  default     = 80
}

variable "tags" {
  description = "Tags to apply to created resources"
  type        = map(string)
  default     = {}
}
