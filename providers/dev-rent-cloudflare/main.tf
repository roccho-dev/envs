# Persistent Cloudflare SSH path for the windows-rent (windows #14-E): one named Tunnel with its ingress, the DNS
# record, a self-hosted Access application and a Service Auth policy for exactly one service token.
#
# Declaration only. No workflow plans or applies this root, and none may until the later gates in README.md are
# agreed: durable encrypted and locked managed state with its ownership and key custody, the backend credential
# boundary, and the service-token lifetime, rotation and delivery plus the Tunnel-token placement. Its state will
# hold both secrets even though the output is sensitive. Every input is required; nothing here adopts, imports or
# moves an existing resource.

terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "5.21.1"
    }
  }

  # Partial native S3 backend: the bucket, key and endpoint are given at init by the later state gate. Backend
  # credentials come only from the process environment, never from this file.
  backend "s3" {
    region                      = "auto"
    use_lockfile                = true
    use_path_style              = true
    skip_credentials_validation = true
    skip_region_validation      = true
    skip_requesting_account_id  = true
    skip_metadata_api_check     = true
    skip_s3_checksum            = true
  }

  # Methods and keys come only from TF_ENCRYPTION; enforced state and plan encryption refuses plaintext without it.
  encryption {
    state {
      enforced = true
    }
    plan {
      enforced = true
    }
  }
}

variable "account_id" {
  type = string
}

variable "zone_id" {
  type = string
}

variable "hostname" {
  type = string
}

# The sshd behind the Tunnel, for example ssh://localhost:22; bound by the deployment gate, not assumed here.
variable "origin_service" {
  type = string
}

# The service token's lifetime is a deployment decision (rotation and delivery are later gates); no default.
variable "service_token_duration" {
  type = string
}

locals {
  name = "windows-rent-ssh"
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "rent" {
  account_id = var.account_id
  name       = local.name
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "rent" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.rent.id
  config = {
    ingress = [
      { hostname = var.hostname, service = var.origin_service },
      { service = "http_status:404" },
    ]
  }
}

resource "cloudflare_dns_record" "rent" {
  zone_id = var.zone_id
  name    = var.hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.rent.id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_zero_trust_access_service_token" "rent" {
  account_id = var.account_id
  name       = local.name
  duration   = var.service_token_duration
}

# Service Auth for exactly this one token; no identity, bypass or any-token rule.
resource "cloudflare_zero_trust_access_policy" "rent" {
  account_id = var.account_id
  name       = local.name
  decision   = "non_identity"
  include    = [{ service_token = { token_id = cloudflare_zero_trust_access_service_token.rent.id } }]
}

resource "cloudflare_zero_trust_access_application" "rent" {
  account_id = var.account_id
  name       = local.name
  domain     = var.hostname
  type       = "self_hosted"
  policies   = [{ id = cloudflare_zero_trust_access_policy.rent.id, precedence = 1 }]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "rent" {
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.rent.id
}

output "credentials" {
  sensitive = true
  value = {
    tunnel_token        = data.cloudflare_zero_trust_tunnel_cloudflared_token.rent.token
    service_token_id    = cloudflare_zero_trust_access_service_token.rent.client_id
    service_token_value = cloudflare_zero_trust_access_service_token.rent.client_secret
  }
}
