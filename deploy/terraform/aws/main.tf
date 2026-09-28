# Terraform configuration for Ziro-OS on AWS

terraform {
  required_version = ">= 1.3" # optional() object attributes
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-west-2"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.medium"
}

variable "cluster_name" {
  description = "Ziro-OS cluster name"
  type        = string
  default     = "ziro-os-cluster"
}

variable "node_count" {
  description = "Number of Ziro-OS nodes"
  type        = number
  default     = 3
}

variable "key_name" {
  description = "AWS key pair name"
  type        = string
}

variable "ssh_allowed_cidrs" {
  description = "CIDRs allowed to reach SSH (22). No default: never open SSH to 0.0.0.0/0 by accident."
  type        = list(string)
}

variable "ziro_version" {
  description = "Ziro-OS release tag whose bootstrap scripts are fetched (pinned, never 'main')"
  type        = string
  default     = "v1.0.9"
}

variable "bootstrap_sha256" {
  description = "Optional sha256 of each bootstrap script at ziro_version; verified when set"
  type = object({
    install_k8s        = optional(string, "")
    install_monitoring = optional(string, "")
    harden             = optional(string, "")
  })
  default = {}
}

# Data sources
data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ziro_os" {
  most_recent = true
  owners      = ["self"]

  filter {
    name   = "name"
    values = ["ziro-os-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# VPC and networking
resource "aws_vpc" "ziro_os" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.cluster_name}-vpc"
    Type = "ziro-os"
  }
}

resource "aws_internet_gateway" "ziro_os" {
  vpc_id = aws_vpc.ziro_os.id

  tags = {
    Name = "${var.cluster_name}-igw"
  }
}

resource "aws_subnet" "ziro_os" {
  count = min(length(data.aws_availability_zones.available.names), 3)

  vpc_id                  = aws_vpc.ziro_os.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.cluster_name}-subnet-${count.index + 1}"
    Type = "ziro-os"
  }
}

resource "aws_route_table" "ziro_os" {
  vpc_id = aws_vpc.ziro_os.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ziro_os.id
  }

  tags = {
    Name = "${var.cluster_name}-rt"
  }
}

resource "aws_route_table_association" "ziro_os" {
  count = length(aws_subnet.ziro_os)

  subnet_id      = aws_subnet.ziro_os[count.index].id
  route_table_id = aws_route_table.ziro_os.id
}

# Security groups
resource "aws_security_group" "ziro_os_nodes" {
  name_prefix = "${var.cluster_name}-nodes"
  vpc_id      = aws_vpc.ziro_os.id

  # SSH access (restricted)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_allowed_cidrs
  }

  # Kubernetes API
  ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Kubelet API
  ingress {
    from_port   = 10250
    to_port     = 10250
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # NodePort services
  ingress {
    from_port   = 30000
    to_port     = 32767
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Container networking
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # Monitoring
  ingress {
    from_port   = 9090
    to_port     = 9100
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  # All outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.cluster_name}-nodes-sg"
  }
}

# Launch template
resource "aws_launch_template" "ziro_os" {
  name_prefix   = "${var.cluster_name}-"
  image_id      = data.aws_ami.ziro_os.id
  instance_type = var.instance_type
  key_name      = var.key_name

  vpc_security_group_ids = [aws_security_group.ziro_os_nodes.id]

  user_data = base64encode(templatefile("${path.module}/user-data.sh", {
    cluster_name              = var.cluster_name
    ziro_version              = var.ziro_version
    install_k8s_sha256        = var.bootstrap_sha256.install_k8s
    install_monitoring_sha256 = var.bootstrap_sha256.install_monitoring
    harden_sha256             = var.bootstrap_sha256.harden
  }))

  # Enforce IMDSv2; hop limit 1 keeps containers from reaching instance credentials
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "${var.cluster_name}-node"
      Type = "ziro-os"
    }
  }

  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group
resource "aws_autoscaling_group" "ziro_os" {
  name                = "${var.cluster_name}-asg"
  vpc_zone_identifier = aws_subnet.ziro_os[*].id
  target_group_arns   = []
  health_check_type   = "EC2"
  health_check_grace_period = 300

  min_size         = 1
  max_size         = 10
  desired_capacity = var.node_count

  launch_template {
    id      = aws_launch_template.ziro_os.id
    version = "$Latest"
  }

  tag {
    key                 = "Name"
    value               = "${var.cluster_name}-asg"
    propagate_at_launch = false
  }

  tag {
    key                 = "Type"
    value               = "ziro-os"
    propagate_at_launch = true
  }
}

# Load balancer for Kubernetes API
resource "aws_lb" "ziro_os_api" {
  name               = "${var.cluster_name}-api-lb"
  internal           = false
  load_balancer_type = "network"
  subnets            = aws_subnet.ziro_os[*].id

  enable_deletion_protection = false

  tags = {
    Name = "${var.cluster_name}-api-lb"
  }
}

resource "aws_lb_target_group" "ziro_os_api" {
  name     = "${var.cluster_name}-api-tg"
  port     = 6443
  protocol = "TCP"
  vpc_id   = aws_vpc.ziro_os.id

  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/healthz"
    port                = "traffic-port"
    protocol            = "HTTPS"
    timeout             = 5
    unhealthy_threshold = 2
  }

  tags = {
    Name = "${var.cluster_name}-api-tg"
  }
}

resource "aws_lb_listener" "ziro_os_api" {
  load_balancer_arn = aws_lb.ziro_os_api.arn
  port              = "6443"
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.ziro_os_api.arn
  }
}

# Outputs
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.ziro_os.id
}

output "subnet_ids" {
  description = "Subnet IDs"
  value       = aws_subnet.ziro_os[*].id
}

output "security_group_id" {
  description = "Security group ID"
  value       = aws_security_group.ziro_os_nodes.id
}

output "load_balancer_dns" {
  description = "Load balancer DNS name"
  value       = aws_lb.ziro_os_api.dns_name
}

output "cluster_endpoint" {
  description = "Kubernetes cluster endpoint"
  value       = "https://${aws_lb.ziro_os_api.dns_name}:6443"
}