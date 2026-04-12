# Free Alternatives to ip-api.com API for IP Data Enrichment

> This is a summarized translation of the original Portuguese document. For the full technical analysis, see [Portuguese version](../Portuguese/ALTERNATIVAS_GRATUITAS_IP_API.md).

## Introduction

The current project uses ip-api.com as the primary IP enrichment source. In practice, the flow is already adapted to receive fields like `country`, `countryCode`, `regionName`, `city`, `org`, `isp`, `as`, `mobile`, `proxy`, `hosting`, `lat`, and `lon`, and convert them to the internal contract used by the system.

When looking for free alternatives, the right question is not just "which free API has the highest quota?" but "which free API delivers data sufficiently compatible with what the system already uses today?"

**In summary**: there are alternatives with more flexible limits than the free version of ip-api.com, but none of them are a perfect drop-in replacement without adaptation.

## Executive Summary

| Alternative | Free use without registration | Free use with registration | Adherence to current project | Main trade-off |
| --- | --- | --- | --- | --- |
| IPinfo Lite | Not the main usage model; usually requires token | Unlimited, no documented daily/monthly limit | Low | Only delivers country, continent, and basic ASN in free tier |
| ipwho.is / ipwhois.io | 1 req/sec, max 60 per 60 sec window, no monthly limit, backend-only | No documented free benefit from registration | Medium | Good geography, but with usage restrictions and no guaranteed security layer equivalence |
| MaxMind GeoLite | Not practical without account/license | Up to 1000 lookups/day via web service, 30 DB downloads/day | Medium | Best for local/offline use, but integration is less direct and free accuracy is lower |
| IP2Location.io | 1000 queries/day in keyless mode | 50K geo queries/month on Free plan | Medium-high | Best HTTP fit with registration, but free plan still doesn't replace all investigative signals |

## Free Registration Quotas Comparison

- **IPinfo Lite**: Unlimited use, no documented daily/monthly limit. Batch endpoint accepts up to 1000 IPs per call.
- **ipwho.is / ipwhois.io**: 1 request per second per client IP, max 60 requests in any 60-second window, no documented monthly limit.
- **MaxMind GeoLite**: Requires account and license key. Free GeoLite allows up to 1000 web service queries/day. Local DB queries depend on your infrastructure.
- **IP2Location.io**: Without registration: 1000 queries/day. With free account: 50K geo queries/month. Best quota elevation among simple HTTP API options.

## Recommendation

For this project, the most practical path when the free ip-api.com quota is insufficient:

1. **Register for IP2Location.io Free** — 50K queries/month with good field coverage
2. **Download MaxMind GeoLite2 DB** — for offline/local enrichment with no quota limits
3. **Keep ip-api.com as primary** — the paid plan ($15/month) offers unlimited HTTPS queries and remains the most compatible option

The paid ip-api.com plan continues to be the best cost-benefit for investigative use given the existing integration.
