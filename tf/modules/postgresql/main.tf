resource "aws_security_group" "pg" {
  description = "controls access to postgresql database"

  vpc_id      = var.vpc_id
  name_prefix = "oonipg"

  ingress {
    protocol        = "tcp"
    from_port       = 5432
    to_port         = 5432
    security_groups = var.allow_security_groups
    cidr_blocks     = var.allow_cidr_blocks
  }

  egress {
    from_port = 0
    to_port   = 0
    protocol  = "-1"

    cidr_blocks = [
      "0.0.0.0/0",
    ]
  }

  lifecycle {
    create_before_destroy = true
  }

  tags = var.tags
}

resource "aws_db_subnet_group" "pg" {
  name       = "${var.name}-dbsng"
  subnet_ids = var.subnet_ids

  tags = merge(
    var.tags,
    { Name = "${var.name}-dbsng" }
  )
}

### PostgreSQL database
resource "aws_db_instance" "pg" {
  allocated_storage           = var.db_allocated_storage
  max_allocated_storage       = var.db_max_allocated_storage
  storage_type                = var.db_storage_type
  engine                      = "postgres"
  engine_version              = var.db_engine_version
  instance_class              = var.db_instance_class
  identifier                  = var.name
  multi_az                    = var.db_multi_az
  db_name                     = var.pg_db_name
  username                    = var.pg_username
  manage_master_user_password = true
  parameter_group_name        = var.db_parameter_group
  db_subnet_group_name        = aws_db_subnet_group.pg.name
  vpc_security_group_ids      = [aws_security_group.pg.id]
  skip_final_snapshot         = true
  backup_retention_period     = 7
  publicly_accessible         = true

  # Enable deletion protection in production
  deletion_protection = true

  # Comment this out in production
  # apply_immediately = true
  tags = var.tags
}
