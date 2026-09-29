# Disposable Access SSH service-token probe for windows #14 (dev only).
#
# create = false (the default) declares no managed resource: the run only looks up the fixed names, so it can never
# delete anything. create = true declares exactly the disposable set below; `destroy` removes only what this state
# created. State lives in the runner's temporary directory and is never committed, cached, uploaded or logged.

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

variable "zone_id" {
  type = string
}

variable "create" {
  type    = bool
  default = false
}

variable "local_port" {
  type    = number
  default = 2222
}

locals {
  name     = "windows-rent-access-probe"
  hostname = "rent-access-probe.roccho.com"
  count    = var.create ? 1 : 0
}

# Lookup by the fixed names: a locator only. A match is never adopted, reused or deleted.
data "cloudflare_zero_trust_tunnel_cloudflareds" "named" {
  account_id = var.account_id
  name       = local.name
  is_deleted = false
}

data "cloudflare_dns_records" "named" {
  zone_id = var.zone_id
  name    = { exact = local.hostname }
}

data "cloudflare_zero_trust_access_applications" "named" {
  account_id = var.account_id
  domain     = local.hostname
  exact      = true
}

data "cloudflare_zero_trust_access_service_tokens" "named" {
  account_id = var.account_id
  name       = local.name
}

output "located" {
  value = {
    tunnels             = [for item in data.cloudflare_zero_trust_tunnel_cloudflareds.named.result : item.id]
    dns_records         = [for item in data.cloudflare_dns_records.named.result : item.id]
    access_applications = [for item in data.cloudflare_zero_trust_access_applications.named.result : item.id]
    service_tokens      = [for item in data.cloudflare_zero_trust_access_service_tokens.named.result : item.id]
  }
}

resource "cloudflare_zero_trust_tunnel_cloudflared" "probe" {
  count      = local.count
  account_id = var.account_id
  name       = local.name
  config_src = "cloudflare"
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "probe" {
  count      = local.count
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.probe[0].id
  config = {
    ingress = [
      { hostname = local.hostname, service = "ssh://localhost:${var.local_port}" },
      { service = "http_status:404" },
    ]
  }
}

resource "cloudflare_dns_record" "probe" {
  count   = local.count
  zone_id = var.zone_id
  name    = local.hostname
  type    = "CNAME"
  content = "${cloudflare_zero_trust_tunnel_cloudflared.probe[0].id}.cfargotunnel.com"
  proxied = true
  ttl     = 1
}

resource "cloudflare_zero_trust_access_service_token" "probe" {
  count      = local.count
  account_id = var.account_id
  name       = local.name
  duration   = "1h"
}

# Service Auth for exactly this one token; no identity, bypass or any-token rule.
resource "cloudflare_zero_trust_access_policy" "probe" {
  count      = local.count
  account_id = var.account_id
  name       = local.name
  decision   = "non_identity"
  include    = [{ service_token = { token_id = cloudflare_zero_trust_access_service_token.probe[0].id } }]
}

resource "cloudflare_zero_trust_access_application" "probe" {
  count      = local.count
  account_id = var.account_id
  name       = local.name
  domain     = local.hostname
  type       = "self_hosted"
  policies   = [{ id = cloudflare_zero_trust_access_policy.probe[0].id, precedence = 1 }]
}

data "cloudflare_zero_trust_tunnel_cloudflared_token" "probe" {
  count      = local.count
  account_id = var.account_id
  tunnel_id  = cloudflare_zero_trust_tunnel_cloudflared.probe[0].id
}

# Exact IDs this state created (non-secret), recorded before the probe and used for cleanup readback.
output "created" {
  value = var.create ? {
    tunnel             = cloudflare_zero_trust_tunnel_cloudflared.probe[0].id
    dns_record         = cloudflare_dns_record.probe[0].id
    access_application = cloudflare_zero_trust_access_application.probe[0].id
    access_policy      = cloudflare_zero_trust_access_policy.probe[0].id
    service_token      = cloudflare_zero_trust_access_service_token.probe[0].id
  } : null
}

output "credentials" {
  sensitive = true
  value = var.create ? {
    tunnel_token        = data.cloudflare_zero_trust_tunnel_cloudflared_token.probe[0].token
    service_token_id    = cloudflare_zero_trust_access_service_token.probe[0].client_id
    service_token_value = cloudflare_zero_trust_access_service_token.probe[0].client_secret
  } : null
}
