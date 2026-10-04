provider "aws" {
  region = "us-west-2"
}

resource "aws_s3_bucket" "reports" {
  bucket = "dep-analyzer-reports-yizec-2026"
}