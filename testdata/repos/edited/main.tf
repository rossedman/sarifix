resource "aws_s3_bucket" "logs" {
  bucket        = "sarifix-fixture-logs"
  force_destroy = false
}

resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH from anywhere (fixture)"
  }
}
