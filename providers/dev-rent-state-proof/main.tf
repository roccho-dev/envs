# Disposable R2 buckets for the windows #8/#14 durable-state proof (dev only).
#
# Exactly two per-run buckets named from the immutable GitHub run identity. decoy = false declares only the proof
# bucket, so the first bounded create is the only capability probe; the decoy exists only to prove that a credential
# bound to the proof bucket cannot reach another bucket. Nothing here names, adopts or deletes an existing bucket or
# the reserved production state bucket. State lives in the runner's temporary directory and is never committed.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }
}

variable "account_id" {
  type = string
}

variable "run" {
  type = string

  validation {
    condition     = can(regex("^[0-9]{1,20}-[0-9]{1,4}$", var.run))
    error_message = "run must be <run_id>-<run_attempt>."
  }
}

variable "decoy" {
  type    = bool
  default = false
}

locals {
  name = "windows-rent-state-proof-${var.run}"
}

resource "cloudflare_r2_bucket" "proof" {
  account_id = var.account_id
  name       = local.name
}

resource "cloudflare_r2_bucket" "decoy" {
  count      = var.decoy ? 1 : 0
  account_id = var.account_id
  name       = "${local.name}-decoy"
}
