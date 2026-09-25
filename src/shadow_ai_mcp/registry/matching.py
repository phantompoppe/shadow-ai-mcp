from __future__ import annotations

from dataclasses import dataclass

from shadow_ai_mcp.models.schemas import RegistryAsset
from shadow_ai_mcp.normalization.core import domain_of, normalize_url


@dataclass(frozen=True)
class Match:
    asset: RegistryAsset
    method: str


def match_assets(
    assets: list[RegistryAsset],
    *,
    asset_id: str | None = None,
    asset_type: str | None = None,
    name: str | None = None,
    endpoint: str | None = None,
    domain: str | None = None,
    server_id: str | None = None,
) -> list[Match]:
    result: list[Match] = []
    for asset in assets:
        if asset_type and asset.asset_type != asset_type:
            continue
        method = None
        if asset_id and asset.asset_id == asset_id:
            method = "asset_id"
        elif server_id and asset.asset_id == server_id:
            method = "mcp_server_id"
        elif endpoint:
            try:
                normalized = normalize_url(endpoint)
                candidates = [asset.canonical_endpoint, *asset.alternate_endpoints]
                method = next(
                    (
                        "canonical_endpoint" if i == 0 else "alternate_endpoint"
                        for i, candidate in enumerate(candidates)
                        if normalized == normalize_url(candidate)
                    ),
                    None,
                )
            except ValueError:
                pass
        if not method and name and asset.name.casefold() == name.casefold():
            method = "name"
        if not method and (domain or endpoint):
            wanted = domain or domain_of(endpoint)
            if wanted and wanted in [
                domain_of(candidate)
                for candidate in [asset.canonical_endpoint, *asset.alternate_endpoints]
            ]:
                method = "domain_alias"
        if method:
            result.append(Match(asset, method))
    priority = {
        "asset_id": 0,
        "mcp_server_id": 1,
        "canonical_endpoint": 2,
        "alternate_endpoint": 3,
        "name": 4,
        "domain_alias": 5,
    }
    return sorted(result, key=lambda x: (priority[x.method], x.asset.asset_id))
