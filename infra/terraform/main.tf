terraform {
  required_version = ">= 0.13"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "3.74.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.0"
    }
    random = "3.1.0"
  }
}

provider "aws" {
  region = "eu-west-1"
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "2.78.0"
  name    = "testbed"
}

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "17.1.0"
}

module "local_thing" {
  source = "./modules/thing"
}

resource "aws_s3_bucket" "logs" {
  bucket = "kagen-testbed-logs"
  acl    = "public-read"
}
