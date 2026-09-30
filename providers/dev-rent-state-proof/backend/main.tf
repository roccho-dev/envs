# OpenTofu S3 backend on one disposable R2 bucket, for the windows #8/#14 durable-state proof (dev only).
#
# Backend credentials come only from the process environment (one bucket-bound temporary R2 credential), never from
# this file or -backend-config. Encryption methods and keys come only from TF_ENCRYPTION; enforced state and
# plan encryption refuses to write plaintext when it is absent. No provider: the resources are built-in.

variable "account_id" {
  type = string
}

variable "bucket" {
  type = string
}

variable "key" {
  type = string
}

variable "canary" {
  type    = string
  default = ""
}

variable "hold_nonce" {
  type    = string
  default = ""
}

variable "hold_seconds" {
  type    = number
  default = 0
}

variable "python" {
  type    = string
  default = ""
}

terraform {
  backend "s3" {
    bucket                      = var.bucket
    key                         = var.key
    region                      = "auto"
    endpoints                   = { s3 = "https://${var.account_id}.r2.cloudflarestorage.com" }
    workspace_key_prefix        = "state/env"
    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }

  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}

resource "terraform_data" "canary" {
  input = var.canary
}

# Holds the native lock file while one contender is refused; the sleep runs on the closure's own interpreter.
resource "terraform_data" "hold" {
  count            = var.hold_seconds > 0 ? 1 : 0
  triggers_replace = var.hold_nonce

  provisioner "local-exec" {
    command     = "import time; time.sleep(${var.hold_seconds})"
    interpreter = [var.python, "-I", "-c"]
  }
}

output "canary" {
  value = terraform_data.canary.output
}
