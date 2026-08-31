mock_provider "cloudflare" {
  mock_data "cloudflare_authenticated_origin_pulls_certificate" {
    defaults = {
      status = "active"
    }
  }
}

variables {
  zone_id                    = "00000000000000000000000000000000"
  domain                     = "lowerduckpond.net"
  origin_ipv4_address        = "203.0.113.10"
  direct_records_enabled     = true
  origin_pull_certificate_id = "11111111111111111111111111111111"
}

run "direct" {
  command = plan

  variables {
    rollout_phase = "direct"
  }

  assert {
    condition = (
      length(cloudflare_dns_record.apex) == 1 &&
      cloudflare_dns_record.apex[0].proxied == false &&
      length(cloudflare_authenticated_origin_pulls_settings.zone) == 0
    )
    error_message = "Direct mode must retain only unproxied DNS."
  }
}

run "direct_without_existing_records" {
  command = plan

  variables {
    direct_records_enabled = false
    rollout_phase          = "direct"
  }

  assert {
    condition = (
      length(cloudflare_dns_record.apex) == 0 &&
      length(cloudflare_dns_record.wildcard) == 0
    )
    error_message = "Direct mode must not invent records in a previously absent zone."
  }
}

run "proxied" {
  command = plan

  variables {
    rollout_phase              = "proxied"
    origin_pull_certificate_id = "11111111-1111-1111-1111-111111111111"
  }

  assert {
    condition = (
      cloudflare_dns_record.apex[0].proxied == true &&
      cloudflare_dns_record.apex[0].ttl == 1 &&
      cloudflare_zone_setting.ssl[0].value == "strict" &&
      cloudflare_zone_setting.always_online[0].value == "off" &&
      cloudflare_authenticated_origin_pulls_settings.zone[0].enabled == true
    )
    error_message = "Proxied mode must install the reviewed public edge."
  }
}

run "enforced" {
  command = plan

  variables {
    rollout_phase = "enforced"
  }

  assert {
    condition     = cloudflare_dns_record.apex[0].proxied == true
    error_message = "Enforced mode must retain the proxied public edge."
  }
}
