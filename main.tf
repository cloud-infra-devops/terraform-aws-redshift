# Example usage of the redshift-cluster module
module "redshift" {
  source = "./modules/redshift-cluster"

  cluster_identifier = "374278-redshift-module-demo"
  vpc_id             = "vpc-07b3e9e8021bfb088"      # must exist in AWS account
  subnet_ids         = ["subnet-0260bb197628ace27"] # must exist in AWS account
  # vpc_security_group_ids = ["sg-0123456789abcdef0"]     # must exist
  # subnet_group_name      = "existing-redshift-subnet-group" # must exist
  db_name         = "analytics"
  master_username = "admin"

  # Let module create KMS key and log bucket
  create_kms_key    = true
  create_log_bucket = true

  # monitoring
  create_monitoring_alarm = true

  tags = {
    Environment = "dev"
    Owner       = "cloud-infra-devops"
  }
}
