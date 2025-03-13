terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.90.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.7.1"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}
#---------------------------------------------
# genrate a random name for s3
#---------------------------------------------
resource "random_id" "random" {
  byte_length = 8
}
#---------------------------------------------
# make a vpc
#---------------------------------------------
resource "aws_vpc" "vpc1" {
  cidr_block = "10.16.0.0/24"
  tags = {
    Name = "vpc1"
  }
}
#---------------------------------------------
# make a public subnet
#---------------------------------------------
resource "aws_subnet" "public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.16.0.0/26"
  availability_zone = "us-east-1a"
  tags = {
    Name = "public"
  }
}
#---------------------------------------------
# make a private subnet
#---------------------------------------------
resource "aws_subnet" "private" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.16.0.64/26"
  availability_zone = "us-east-1b"
  tags = {
    Name = "private"
  }
}
#---------------------------------------------
# make a private subnet for database
#---------------------------------------------
resource "aws_subnet" "private1" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.16.0.128/26"
  availability_zone = "us-east-1c"
  tags = {
    Name = "private"
  }
}
#---------------------------------------------
# make a internet gateway
#---------------------------------------------
resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = "igw"
  }
}
#---------------------------------------------
# make a route table for public subnet
#---------------------------------------------
resource "aws_route_table" "rt-pub" {
  vpc_id = aws_vpc.vpc1.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "rt"
  }
}
#---------------------------------------------
# associate the route table with the public subnet
#---------------------------------------------
resource "aws_route_table_association" "rta" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.rt-pub.id
}
#---------------------------------------------
# make a security group for nat instance
#---------------------------------------------
resource "aws_security_group" "nat-sg" {
  vpc_id = aws_vpc.vpc1.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
#---------------------------------------------
# make a nat instance
#---------------------------------------------
resource "aws_instance" "nat" {
  ami             = "ami-04aa00acb1165b32a"
  instance_type   = "t2.micro"
  subnet_id       = aws_subnet.public.id
  security_groups = [aws_security_group.nat-sg.id]
  key_name        = "us-east"
  tags = {
    Name = "nat-instance"
  }

  user_data = <<-EOF
    #!/bin/bash
    sysctl -w net.ipv4.ip_forward=1
    iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
  EOF
}
#---------------------------------------------
# create a eip for the nat instance
#---------------------------------------------
resource "aws_eip" "eip" {
  network_interface = aws_instance.nat.primary_network_interface_id
}
#---------------------------------------------
# route table for private subnet
#---------------------------------------------
resource "aws_route_table" "rt-priv" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = "rt-priv"
  }
}
#---------------------------------------------
# make a route for nat-instance
#---------------------------------------------
resource "aws_route" "route" {
  route_table_id         = aws_route_table.rt-priv.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_instance.nat.primary_network_interface_id
}
#---------------------------------------------
# associate the route table with the private subnet
#---------------------------------------------
resource "aws_route_table_association" "rta-priv" {
  subnet_id      = aws_subnet.private.id
  route_table_id = aws_route_table.rt-priv.id
}

#---------------------------------------------
# make a security group for load balancer
#---------------------------------------------
resource "aws_security_group" "lb_sg" {
  vpc_id = aws_vpc.vpc1.id
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.private.cidr_block]
  }

  tags = {
    Name = "load-balancer-sg"
  }
}

#---------------------------------------------
# make a security group for ec2
#---------------------------------------------
resource "aws_security_group" "ec2" {
  vpc_id = aws_vpc.vpc1.id

  ingress {
    from_port       = 80
    to_port         = 80
    protocol        = "tcp"
    security_groups = [aws_security_group.lb_sg.id]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "web-server-sg"
  }
}
#---------------------------------------------
# make a security group for database
#---------------------------------------------
resource "aws_security_group" "db_sg" {
  vpc_id = aws_vpc.vpc1.id

  ingress {
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "database-sg"
  }
}
#---------------------------------------------
# make public ec2 instance
#---------------------------------------------
resource "aws_instance" "public" {
  ami                  = "ami-08b5b3a93ed654d19"
  instance_type        = "t2.micro"
  subnet_id            = aws_subnet.public.id
  security_groups      = [aws_security_group.ec2.id]
  key_name             = "us-east"
  iam_instance_profile = aws_iam_instance_profile.ec2_profile.name
  availability_zone    = "us-east-1a"
  tags = {
    Name = "public-instance"
  }
}
#---------------------------------------------
# eip for ec2
#---------------------------------------------
resource "aws_eip" "pub-eip" {
  network_interface = aws_instance.public.primary_network_interface_id
}
#---------------------------------------------
# make a load balancer
#---------------------------------------------
resource "aws_lb" "lb1" {
  name                       = "lb1"
  internal                   = false
  load_balancer_type         = "application"
  security_groups            = [aws_security_group.lb_sg.id]
  subnets                    = [aws_subnet.public.id, aws_subnet.private1.id]
  enable_deletion_protection = false
}
#---------------------------------------------
# make a target group
#---------------------------------------------
resource "aws_lb_target_group" "tg" {
  name     = "tg"
  port     = 80
  protocol = "HTTP"
  vpc_id   = aws_vpc.vpc1.id
}
#---------------------------------------------
# attach target group to ec2
#---------------------------------------------
resource "aws_lb_target_group_attachment" "test" {
  target_group_arn = aws_lb_target_group.tg.arn
  target_id        = aws_instance.public.id
  port             = 80
}
#---------------------------------------------
# make a launch template
#---------------------------------------------
resource "aws_launch_template" "ec2" {
  name = "ec2"

  block_device_mappings {
    device_name = "/dev/xvda"

    ebs {
      volume_size = 20
    }
  }

  ebs_optimized = true

  image_id = "ami-08b5b3a93ed654d19"

  instance_initiated_shutdown_behavior = "terminate"

  instance_type = "t2.micro"

  key_name = "us-east"

  network_interfaces {
    associate_public_ip_address = true
    security_groups             = [aws_security_group.ec2.id]
  }


  iam_instance_profile {
    name = aws_iam_instance_profile.ec2_profile.name
  }

  placement {
    availability_zone = "us-east-1a"
  }

  tags = {
    Name = "test"
  }
}
#---------------------------------------------
# make a auto scaling group
#---------------------------------------------
resource "aws_autoscaling_group" "asg" {
  desired_capacity = 1
  max_size         = 3
  min_size         = 1
  launch_template {
    id      = aws_launch_template.ec2.id
    version = "$Latest"
  }
  vpc_zone_identifier = [aws_subnet.public.id]
}
#---------------------------------------------
# make a subnet group for database
#---------------------------------------------
resource "aws_db_subnet_group" "rds_subnet_group" {
  name       = "my-db-subnet-group"
  subnet_ids = [aws_subnet.private.id, aws_subnet.private1.id]
}
#---------------------------------------------
# make a  mysql database
#---------------------------------------------
resource "aws_db_instance" "mysql" {
  allocated_storage      = 20
  db_name                = "mydb"
  engine                 = "mysql"
  engine_version         = "8.0"
  instance_class         = "db.t4g.micro"
  username               = "admin"
  password               = "piyush1234"
  parameter_group_name   = "default.mysql8.0"
  skip_final_snapshot    = true
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.rds_subnet_group.name
}

#---------------------------------------------
# make a s3 bucket
#---------------------------------------------
resource "aws_s3_bucket" "s3" {
  bucket = "malpani-${random_id.random.hex}"
  tags = {
    Name = "malpani-007-piyush"
  }
}
#---------------------------------------------
# Bucket Policy for CloudFront Logs Bucket
#---------------------------------------------
resource "aws_s3_bucket_policy" "combined_s3_policy" {
  bucket = aws_s3_bucket.s3.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        # CloudFront read access
        Effect = "Allow",
        Principal = {
          Service = "cloudfront.amazonaws.com"
        },
        Action   = "s3:GetObject",
        Resource = "${aws_s3_bucket.s3.arn}/*"
      },
      {
        # CloudFront logging permission
        Sid    = "AWSCloudFrontLogsPolicy",
        Effect = "Allow",
        Principal = {
          Service = "cloudfront.amazonaws.com"
        },
        Action   = "s3:PutObject",
        Resource = "${aws_s3_bucket.s3.arn}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      },
      {
        # Full access for EC2 role
        Effect = "Allow",
        Principal = {
          AWS = "${aws_iam_role.ec2_role.arn}"
        },
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ],
        Resource = [
          "${aws_s3_bucket.s3.arn}/*",
          "${aws_s3_bucket.s3.arn}"
        ]
      }
    ]
  })
}

locals {
  s3_origin_id = "myS3Origin"
}
#---------------------------------------------
# CloudFront Origin Access Control
#---------------------------------------------
resource "aws_cloudfront_origin_access_control" "default" {
  name                              = "my-oac"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}
#---------------------------------------------
# IAM Role for EC2 with S3 Access
#---------------------------------------------
resource "aws_iam_role" "ec2_role" {
  name = "ec2-s3-access-role"

  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

#---------------------------------------------
# IAM Policy for EC2 S3 Access
#---------------------------------------------
resource "aws_iam_policy" "s3_policy" {
  name        = "ec2-s3-policy"
  description = "Allow EC2 to access S3 bucket"

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "${aws_s3_bucket.s3.arn}",
        "${aws_s3_bucket.s3.arn}/*"
      ]
    }
  ]
}
EOF
}

#---------------------------------------------
# Attach IAM Policy to IAM Role
#---------------------------------------------
resource "aws_iam_role_policy_attachment" "ec2_s3_attach" {
  policy_arn = aws_iam_policy.s3_policy.arn
  role       = aws_iam_role.ec2_role.name
}

#---------------------------------------------
# Instance Profile for EC2
#---------------------------------------------
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-profile"
  role = aws_iam_role.ec2_role.name
}
#---------------------------------------------
# adding ip sets for waf
#---------------------------------------------
resource "aws_wafv2_ip_set" "blocked_ips" {
  name               = "blocked-ips"
  description        = "List of IP addresses to block"
  scope              = "CLOUDFRONT" 
  ip_address_version = "IPV4"
  addresses = [
    "203.0.113.0/24", 
    "198.51.100.0/24"
  ]
}
#---------------------------------------------
# adding waf with ipsets
#---------------------------------------------
resource "aws_wafv2_web_acl" "waf" {
  name        = "my-waf"
  description = "WAF for CloudFront distribution with IP Set protection only"
  scope       = "CLOUDFRONT" 
  default_action {
    allow {} 
  }
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "myWafMetric"
    sampled_requests_enabled   = true
  }

  rule {
    name     = "BlockBadIPs"
    priority = 1
    action {
      block {} 
    }
    statement {
      ip_set_reference_statement {
        arn = aws_wafv2_ip_set.blocked_ips.arn
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "BlockBadIPsMetric"
      sampled_requests_enabled   = true
    }
  }
}
#---------------------------------------------
# making a CloudFront Distribution
#---------------------------------------------
resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name              = aws_s3_bucket.s3.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.default.id
    origin_id                = local.s3_origin_id
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "Some comment"
  default_root_object = "index.html"


  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy = "allow-all"
    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
  }

  ordered_cache_behavior {
    path_pattern     = "/content/immutable/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false
      headers      = ["Origin"]

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  ordered_cache_behavior {
    path_pattern     = "/content/*"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = local.s3_origin_id

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 3600
    max_ttl                = 86400
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_200"

  restrictions {
    geo_restriction {
      restriction_type = "blacklist"
      locations        = ["US", "CA", "GB", "DE"]
    }
  }

  tags = {
    Environment = "production"
  }

  web_acl_id = aws_wafv2_web_acl.waf.arn

  viewer_certificate {
    cloudfront_default_certificate = true
  }
}
#---------------------------------------------
# output section
#---------------------------------------------
output "s3" {
  value = random_id.random.hex
}

output "cloudfront" {
  value = aws_cloudfront_distribution.s3_distribution.domain_name
}