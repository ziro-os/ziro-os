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

variable "nodeport_allowed_cidrs" {
  description = "CIDRs allowed to reach NodePort services (30000-32767). Empty: VPC-internal only."
  type        = list(string)
  default     = []
}

variable "api_lb_internal" {
  description = "Keep the Kubernetes API load balancer internal to the VPC (reach it through a VPN, WireGuard peer or bastion)"
  type        = bool
  default     = true
}

variable "public_node_ips" {
  description = "Put nodes in public subnets with public IPs (instead of private subnets behind a NAT gateway)"
  type        = bool
  default     = false
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

locals {
  az_count = min(length(data.aws_availability_zones.available.names), 3)
}

# Public subnets: the NAT gateway and, when api_lb_internal = false, the API load balancer.
resource "aws_subnet" "public" {
  count = local.az_count

  vpc_id            = aws_vpc.ziro_os.id
  cidr_block        = "10.0.${count.index + 101}.0/24"
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.cluster_name}-public-${count.index + 1}"
    Type = "ziro-os"
  }
}

# Node subnets: private (egress through the NAT gateway) unless public_node_ips = true.
resource "aws_subnet" "ziro_os" {
  count = local.az_count

  vpc_id                  = aws_vpc.ziro_os.id
  cidr_block              = "10.0.${count.index + 1}.0/24"
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = var.public_node_ips

  tags = {
    Name = "${var.cluster_name}-subnet-${count.index + 1}"
    Type = "ziro-os"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ziro_os.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ziro_os.id
  }

  tags = {
    Name = "${var.cluster_name}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = local.az_count

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ponytail: one NAT gateway (cost); add one per AZ if an AZ outage must not cut node egress.
resource "aws_eip" "nat" {
  count  = var.public_node_ips ? 0 : 1
  domain = "vpc"

  tags = {
    Name = "${var.cluster_name}-nat"
  }
}

resource "aws_nat_gateway" "ziro_os" {
  count         = var.public_node_ips ? 0 : 1
  allocation_id = aws_eip.nat[0].id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "${var.cluster_name}-nat"
  }

  depends_on = [aws_internet_gateway.ziro_os]
}

resource "aws_route_table" "ziro_os" {
  vpc_id = aws_vpc.ziro_os.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = var.public_node_ips ? null : aws_nat_gateway.ziro_os[0].id
    gateway_id     = var.public_node_ips ? aws_internet_gateway.ziro_os.id : null
  }

  tags = {
    Name = "${var.cluster_name}-nodes-rt"
  }
}

resource "aws_route_table_association" "ziro_os" {
  count = local.az_count

  subnet_id      = aws_subnet.ziro_os[count.index].id
  route_table_id = aws_route_table.ziro_os.id
}

# Security groups
resource "aws_security_group" "ziro_os_nodes" {
  name_prefix = "${var.cluster_name}-nodes"
  description = "Ziro-OS cluster nodes: SSH from allowed CIDRs, cluster traffic inside the VPC, NodePorts from allowed CIDRs"
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

  # NodePort services: only from the CIDRs you list (VPC-internal traffic is allowed below)
  dynamic "ingress" {
    for_each = length(var.nodeport_allowed_cidrs) > 0 ? [1] : []
    content {
      description = "NodePort services"
      from_port   = 30000
      to_port     = 32767
      protocol    = "tcp"
      cidr_blocks = var.nodeport_allowed_cidrs
    }
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

  # Outbound: anything inside the VPC; to the internet only what a container host needs
  # (HTTPS/HTTP for images and packages, DNS, NTP, WireGuard for mesh peers outside the VPC).
  egress {
    description = "Cluster traffic inside the VPC"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    description = "HTTPS (registries, packages, APIs)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "HTTP (package mirrors)"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "NTP"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "WireGuard mesh and remote peers"
    from_port   = 51821
    to_port     = 51821
    protocol    = "udp"
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
  name                      = "${var.cluster_name}-asg"
  vpc_zone_identifier       = aws_subnet.ziro_os[*].id
  target_group_arns         = [aws_lb_target_group.ziro_os_api.arn] # nodes serve the API through the NLB
  health_check_type         = "EC2"
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
  internal           = var.api_lb_internal
  load_balancer_type = "network"
  subnets            = var.api_lb_internal ? aws_subnet.ziro_os[*].id : aws_subnet.public[*].id

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