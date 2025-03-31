Terraform AWS Infrastructure Deployment
This repository contains Terraform configuration to create a comprehensive AWS infrastructure. It provisions various AWS resources, including a VPC, subnets, NAT instance, load balancer, EC2 instances, RDS MySQL database, S3 bucket (with generated unique name), CloudFront distribution, WAF, and IAM roles/policies.

Overview
The configuration performs the following tasks:

Providers:
Uses AWS (v5.90.0) and Random (v3.7.1) providers.

Networking:
Creates a VPC with CIDR 10.16.0.0/24, public and private subnets, an Internet Gateway, and appropriate route tables for public and private connectivity.

Security:
Sets up security groups for NAT, load balancer, web servers, and databases. It also defines a WAF with an IP set to block unwanted traffic.

Compute:
Provisions a NAT instance for outbound connectivity, a public EC2 instance, and an autoscaling group using a launch template.

Database:
Deploys a MySQL RDS instance in a private subnet group.

Storage & CDN:
Creates an S3 bucket with a randomized name and an S3 bucket policy to allow CloudFront logging and EC2 access. A CloudFront distribution with multiple cache behaviors and an Origin Access Control is configured for content delivery.

IAM:
Defines an IAM role and policy for EC2 instances to securely access the S3 bucket.

Prerequisites
Terraform v1.0+ installed

AWS credentials configured (e.g., via the AWS CLI or environment variables)

A pre-existing key pair in AWS with the name us-east
