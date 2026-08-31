mock_provider "cloudflare" {
  mock_data "cloudflare_authenticated_origin_pulls_certificate" {
    defaults = {
      id          = "11111111-1111-1111-1111-111111111111"
      status      = "active"
      uploaded_on = "2026-08-31T00:00:00Z"
    }
  }
  mock_data "cloudflare_authenticated_origin_pulls_certificates" {
    defaults = {
      result = [{
        certificate   = "example-public-certificate"
        expires_on    = "2027-08-31T00:00:00Z"
        id            = "11111111-1111-1111-1111-111111111111"
        issuer        = "example-issuer"
        serial_number = "01"
        signature     = "SHA256WithRSA"
        status        = "active"
        uploaded_on   = "2026-08-31T00:00:00Z"
      }]
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
      cloudflare_zone_setting.always_use_https[0].value == "off" &&
      cloudflare_authenticated_origin_pulls_settings.zone[0].enabled == true
    )
    error_message = "Proxied mode must install the reviewed public edge."
  }
}

run "rejects_a_selected_leaf_that_is_not_newest" {
  command = plan

  override_data {
    target = data.cloudflare_authenticated_origin_pulls_certificates.zone
    values = {
      result = [
        {
          certificate   = "selected-public-certificate"
          expires_on    = "2027-08-31T00:00:00Z"
          id            = "11111111-1111-1111-1111-111111111111"
          issuer        = "example-issuer"
          serial_number = "01"
          signature     = "SHA256WithRSA"
          status        = "active"
          uploaded_on   = "2026-08-31T00:00:00Z"
        },
        {
          certificate   = "newest-public-certificate"
          expires_on    = "2027-08-31T01:00:00Z"
          id            = "22222222-2222-2222-2222-222222222222"
          issuer        = "example-issuer"
          serial_number = "02"
          signature     = "SHA256WithRSA"
          status        = "active"
          uploaded_on   = "2026-08-31T01:00:00Z"
        },
      ]
    }
  }

  variables {
    rollout_phase              = "proxied"
    origin_pull_certificate_id = "11111111-1111-1111-1111-111111111111"
  }

  expect_failures = [cloudflare_authenticated_origin_pulls_settings.zone]
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
