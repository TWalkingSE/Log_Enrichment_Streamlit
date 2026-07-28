"""Domain value helpers for IP enrichment results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class EnrichedIP:
    ip: str
    org: str = ""
    asn: str = ""
    city: str = ""
    region: str = ""
    country: str = ""
    country_code: str = ""
    mobile: bool = False
    proxy: bool = False
    hosting: bool = False
    lat: Optional[float] = None
    lon: Optional[float] = None
    status: str = "unknown"
    extras: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_api_dict(cls, ip: str, data: Dict[str, Any]) -> "EnrichedIP":
        return cls(
            ip=ip,
            org=str(data.get("Ip_Dono") or ""),
            asn=str(data.get("Ip_AS") or ""),
            city=str(data.get("Ip_Cidade") or ""),
            region=str(data.get("Ip_Regiao") or ""),
            country=str(data.get("Ip_Pais") or ""),
            country_code=str(data.get("Ip_Pais_Codigo") or ""),
            mobile=bool(data.get("Ip_Movel", False)),
            proxy=bool(data.get("Ip_Proxy", False)),
            hosting=bool(data.get("Ip_Hospedagem", False)),
            lat=data.get("Ip_Lat"),
            lon=data.get("Ip_Lon"),
            status=str(data.get("status") or "unknown"),
            extras={k: v for k, v in data.items() if k.startswith("_")},
        )

    def to_api_dict(self) -> Dict[str, Any]:
        d = {
            "Ip_Dono": self.org,
            "Ip_AS": self.asn,
            "Ip_Cidade": self.city,
            "Ip_Regiao": self.region,
            "Ip_Pais": self.country,
            "Ip_Pais_Codigo": self.country_code,
            "Ip_Movel": self.mobile,
            "Ip_Proxy": self.proxy,
            "Ip_Hospedagem": self.hosting,
            "Ip_Lat": self.lat,
            "Ip_Lon": self.lon,
            "status": self.status,
        }
        d.update(self.extras)
        return d
