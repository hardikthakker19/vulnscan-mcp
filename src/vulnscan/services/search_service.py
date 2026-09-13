"""Data fusion engine — merges NVD + KEV + EPSS + ATT&CK results."""

from __future__ import annotations

import json
import logging
from typing import Any

from vulnscan.clients.epss_client import EPSSClient
from vulnscan.clients.mitre_client import MITREClient
from vulnscan.clients.nvd_client import NVDClient
from vulnscan.database import queries
from vulnscan.database.connection import get_connection

logger = logging.getLogger(__name__)

_mitre_client = MITREClient()


def _parse_affected_products_and_versions(
    cpe_raw: str | None,
) -> tuple[list[str], list[dict[str, Any]]]:
    """Parse CPE match JSON into human-readable affected versions and structured products list."""
    if not cpe_raw:
        return [], []

    try:
        data = json.loads(cpe_raw)
    except (json.JSONDecodeError, TypeError):
        return [], []

    if not isinstance(data, list):
        return [], []

    affected_versions: list[str] = []
    affected_products: list[dict[str, Any]] = []

    for item in data:
        if isinstance(item, dict):
            affected_products.append(item)
            vendor = item.get("vendor", "")
            product = item.get("product", "")
            cpe = item.get("criteria", "")

            # If vendor/product not explicitly set, extract from criteria
            if (not vendor or not product) and cpe:
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor = vendor or parts[3]
                    product = product or parts[4]

            name = product or vendor or "software"
            if vendor and product and vendor.lower() not in product.lower():
                name = f"{vendor} {product}"

            # Collect version bounds
            v_parts: list[str] = []
            if item.get("versionStartIncluding"):
                v_parts.append(f">= {item['versionStartIncluding']}")
            elif item.get("versionStartExcluding"):
                v_parts.append(f"> {item['versionStartExcluding']}")

            if item.get("versionEndIncluding"):
                v_parts.append(f"<= {item['versionEndIncluding']}")
            elif item.get("versionEndExcluding"):
                v_parts.append(f"< {item['versionEndExcluding']}")

            version = item.get("version")
            if version and version not in ("*", "-"):
                v_parts.append(f"== {version}")

            if v_parts:
                desc = f"{name} {', '.join(v_parts)}"
            else:
                desc = f"{name} (all versions)"

            if desc not in affected_versions:
                affected_versions.append(desc)

        elif isinstance(item, str):
            # CPE 2.3 string: cpe:2.3:part:vendor:product:version:...
            parts = item.split(":")
            if len(parts) >= 5:
                vendor = parts[3]
                product = parts[4]
                version = parts[5] if len(parts) > 5 else "*"
                name = product if vendor.lower() in product.lower() else f"{vendor} {product}"
                entry: dict[str, Any] = {"vendor": vendor, "product": product, "criteria": item}
                if version and version not in ("*", "-"):
                    entry["version"] = version
                    desc = f"{name} == {version}"
                else:
                    desc = f"{name} (all versions)"
                affected_products.append(entry)
                if desc not in affected_versions:
                    affected_versions.append(desc)

    return affected_versions, affected_products


def _format_cve_summary(row: dict[str, Any]) -> dict[str, Any]:
    """Format a CVE database row into a clean summary dict."""
    # Affected products & versions
    affected_versions, affected_products = _parse_affected_products_and_versions(
        row.get("cpe_match_json")
    )

    cve_id = row.get("cve_id")
    result = {
        "cve_id": cve_id,
        "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
        "description": row.get("description", "")[:500],
        "severity": row.get("severity"),
        "cvss_v3_score": row.get("cvss_v3_score"),
        "cvss_v3_vector": row.get("cvss_v3_vector"),
        "published_date": row.get("published_date"),
        "last_modified_date": row.get("last_modified_date"),
        "affected_versions": affected_versions,
    }

    if affected_products:
        result["affected_products"] = affected_products

    # CVSS v4 if available
    if row.get("cvss_v4_score"):
        result["cvss_v4_score"] = row["cvss_v4_score"]
        result["cvss_v4_vector"] = row.get("cvss_v4_vector")

    # KEV enrichment
    if row.get("kev_date_added"):
        result["kev"] = {
            "in_kev": True,
            "date_added": row["kev_date_added"],
            "due_date": row.get("kev_due_date"),
            "required_action": row.get("kev_required_action"),
            "ransomware_use": row.get("kev_ransomware"),
        }
    else:
        result["kev"] = {"in_kev": False}

    # EPSS enrichment
    if row.get("epss_score") is not None:
        result["epss"] = {
            "score": row["epss_score"],
            "percentile": row.get("epss_percentile"),
        }

    # CWE IDs
    cwe_raw = row.get("cwe_ids")
    if cwe_raw:
        try:
            result["cwe_ids"] = json.loads(cwe_raw)
        except (json.JSONDecodeError, TypeError):
            pass

    return result


def _format_cve_detail(row: dict[str, Any]) -> dict[str, Any]:
    """Format a full CVE detail row with all enrichments."""
    result = _format_cve_summary(row)

    # Extended description
    result["description"] = row.get("description", "")

    # References
    refs_raw = row.get("references_json")
    if refs_raw:
        try:
            result["references"] = json.loads(refs_raw)
        except (json.JSONDecodeError, TypeError):
            pass

    # CPE matches
    cpe_raw = row.get("cpe_match_json")
    if cpe_raw:
        try:
            result["affected_products"] = json.loads(cpe_raw)
        except (json.JSONDecodeError, TypeError):
            pass

    # Extended KEV info
    if row.get("kev_date_added"):
        result["kev"]["vendor"] = row.get("kev_vendor")
        result["kev"]["product"] = row.get("kev_product")
        result["kev"]["vulnerability_name"] = row.get("kev_vuln_name")
        result["kev"]["description"] = row.get("kev_description")
        result["kev"]["notes"] = row.get("kev_notes")

    # EPSS extended
    if row.get("epss_score") is not None:
        result["epss"]["date"] = row.get("epss_date")

    # ATT&CK mappings
    attack_mappings = row.get("attack_mappings", [])
    if attack_mappings:
        result["mitre_attack"] = [
            {
                "tactic": f"{m['tactic_id']} — {m['tactic_name']}",
                "technique": f"{m['technique_id']} — {m['technique_name']}",
                "capec_id": m.get("capec_id"),
            }
            for m in attack_mappings
        ]
    else:
        # Try to derive from CWE IDs
        cwe_ids = result.get("cwe_ids", [])
        if cwe_ids:
            derived = _mitre_client.get_attack_mappings(cwe_ids)
            if derived:
                result["mitre_attack"] = [
                    {
                        "tactic": f"{m['tactic_id']} — {m['tactic_name']}",
                        "technique": f"{m['technique_id']} — {m['technique_name']}",
                        "capec_id": m.get("capec_id"),
                    }
                    for m in derived
                ]

    # Risk assessment summary
    risk_factors = []
    if result.get("kev", {}).get("in_kev"):
        risk_factors.append("ACTIVELY EXPLOITED (CISA KEV)")
    epss_score = result.get("epss", {}).get("score")
    if epss_score and epss_score > 0.5:
        risk_factors.append(f"HIGH EXPLOITATION PROBABILITY (EPSS: {epss_score:.4f})")
    elif epss_score and epss_score > 0.1:
        risk_factors.append(f"ELEVATED EXPLOITATION PROBABILITY (EPSS: {epss_score:.4f})")
    cvss = result.get("cvss_v3_score")
    if cvss and cvss >= 9.0:
        risk_factors.append(f"CRITICAL CVSS ({cvss})")
    if result.get("kev", {}).get("ransomware_use") == "Known":
        risk_factors.append("KNOWN RANSOMWARE USAGE")
    if risk_factors:
        result["risk_assessment"] = risk_factors

    return result


async def _enrich_from_nvd(cve_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch full CVE details on-demand from NVD API for CVEs with missing CVSS or CPE data, and update DB."""
    enriched: dict[str, dict[str, Any]] = {}
    if not cve_ids:
        return enriched

    client = NVDClient()
    try:
        for cve_id in cve_ids:
            try:
                results = await client.search_cves(cve_id=cve_id)
                if results:
                    cve_data = results[0]
                    # Persist all NVD data (CVSS v3/v4, severity, vectors, CPEs, CWEs, refs) to DB
                    await queries.upsert_cves([cve_data])

                    versions, products = _parse_affected_products_and_versions(
                        cve_data.get("cpe_match_json")
                    )
                    enriched[cve_id] = {
                        "cvss_v3_score": cve_data.get("cvss_v3_score"),
                        "cvss_v3_vector": cve_data.get("cvss_v3_vector"),
                        "cvss_v4_score": cve_data.get("cvss_v4_score"),
                        "cvss_v4_vector": cve_data.get("cvss_v4_vector"),
                        "severity": cve_data.get("severity"),
                        "versions": versions,
                        "products": products,
                    }
            except Exception as e:
                logger.debug(f"Failed to fetch on-demand NVD data for {cve_id}: {e}")
    finally:
        await client.close()

    return enriched


async def search_vulnerabilities(
    keyword: str | None = None,
    severity: str | None = None,
    pub_start_date: str | None = None,
    pub_end_date: str | None = None,
    has_kev: bool = False,
    limit: int = 20,
) -> dict[str, Any]:
    """Search vulnerabilities with full enrichment."""
    rows = await queries.search_cves(
        keyword=keyword,
        severity=severity,
        pub_start_date=pub_start_date,
        pub_end_date=pub_end_date,
        has_kev=has_kev,
        limit=limit,
    )

    results = [_format_cve_summary(row) for row in rows]

    # For any search results missing CVSS scores or affected versions, attempt quick on-demand NVD enrichment
    missing_cves = [
        r["cve_id"]
        for r in results
        if (r.get("cvss_v3_score") is None or not r.get("affected_versions")) and r.get("cve_id")
    ]
    if missing_cves:
        try:
            enriched = await _enrich_from_nvd(missing_cves[:10])
            for r in results:
                cid = r.get("cve_id")
                if cid in enriched:
                    data = enriched[cid]
                    if data.get("cvss_v3_score") is not None:
                        r["cvss_v3_score"] = data["cvss_v3_score"]
                        r["cvss_v3_vector"] = data.get("cvss_v3_vector")
                    if data.get("cvss_v4_score") is not None:
                        r["cvss_v4_score"] = data["cvss_v4_score"]
                        r["cvss_v4_vector"] = data.get("cvss_v4_vector")
                    if data.get("severity"):
                        r["severity"] = data["severity"]
                    if data.get("versions"):
                        r["affected_versions"] = data["versions"]
                    if data.get("products"):
                        r["affected_products"] = data["products"]
        except Exception as e:
            logger.debug(f"On-demand NVD enrichment error: {e}")

    return {
        "total_results": len(results),
        "filters_applied": {
            "keyword": keyword,
            "severity": severity,
            "pub_start_date": pub_start_date,
            "pub_end_date": pub_end_date,
            "has_kev": has_kev,
        },
        "vulnerabilities": results,
    }


async def get_cve_details(cve_id: str) -> dict[str, Any]:
    """Get comprehensive details for a specific CVE."""
    row = await queries.get_cve_by_id(cve_id)

    if not row or (row.get("cvss_v3_score") is None and not row.get("raw_nvd_json")):
        # On-demand fetch from NVD API if not in local DB or if present only as a stub
        client = NVDClient()
        try:
            nvd_results = await client.search_cves(cve_id=cve_id)
            if nvd_results:
                await queries.upsert_cves(nvd_results)
                row = await queries.get_cve_by_id(cve_id)
        except Exception as e:
            logger.debug(f"Failed to fetch {cve_id} on-demand from NVD: {e}")
        finally:
            await client.close()

    if not row:
        return {
            "error": f"CVE {cve_id} not found in local database or NVD",
            "suggestion": "The CVE may not have been published yet or is invalid.",
        }

    detail = _format_cve_detail(row)
    if not detail.get("affected_versions"):
        try:
            enriched = await _enrich_from_nvd([cve_id])
            if cve_id in enriched:
                detail["affected_versions"] = enriched[cve_id]["versions"]
                if enriched[cve_id]["products"]:
                    detail["affected_products"] = enriched[cve_id]["products"]
        except Exception as e:
            logger.debug(f"On-demand enrichment error for {cve_id}: {e}")

    return detail


async def get_latest_critical(
    days: int = 7,
    min_cvss: float = 9.0,
    limit: int = 10,
) -> dict[str, Any]:
    """Get recently published critical vulnerabilities."""
    rows = await queries.get_latest_critical(
        days=days,
        min_cvss=min_cvss,
        limit=limit,
    )

    results = [_format_cve_summary(row) for row in rows]

    return {
        "query": {
            "days": days,
            "min_cvss": min_cvss,
            "limit": limit,
        },
        "total_results": len(results),
        "vulnerabilities": results,
    }


async def get_top_kevs(
    limit: int = 10,
    sort_by: str = "date_added",
) -> dict[str, Any]:
    """Get top actively exploited vulnerabilities."""
    rows = await queries.get_top_kev_entries(limit=limit, sort_by=sort_by)

    results = []
    for row in rows:
        cve_id = row.get("cve_id")
        entry = {
            "cve_id": cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            "vendor_project": row.get("vendor_project"),
            "product": row.get("product"),
            "vulnerability_name": row.get("vulnerability_name"),
            "date_added": row.get("date_added"),
            "due_date": row.get("due_date"),
            "required_action": row.get("required_action"),
            "known_ransomware_campaign_use": row.get(
                "known_ransomware_campaign_use"
            ),
            "description": row.get("description", "")[:300],
            "severity": row.get("severity"),
            "cvss_v3_score": row.get("cvss_v3_score"),
        }

        if row.get("epss_score") is not None:
            entry["epss"] = {
                "score": row["epss_score"],
                "percentile": row.get("epss_percentile"),
            }

        results.append(entry)

    return {
        "sort_by": sort_by,
        "total_results": len(results),
        "kev_entries": results,
    }


async def get_epss_scores(cve_ids: list[str]) -> dict[str, Any]:
    """Get EPSS scores, fetching from API if not cached."""
    # First check cache
    cached = await queries.get_epss_scores(cve_ids)
    cached_ids = {r["cve_id"] for r in cached}

    # Fetch missing from API
    missing_ids = [cid for cid in cve_ids if cid not in cached_ids]

    api_results = []
    if missing_ids:
        client = EPSSClient()
        try:
            api_results = await client.get_scores(missing_ids)
            if api_results:
                await queries.upsert_epss_scores(api_results)
        except Exception as e:
            logger.warning(f"EPSS API lookup failed: {e}")
        finally:
            await client.close()

    # Combine results
    all_scores = {}
    for r in cached:
        cid = r["cve_id"]
        all_scores[cid] = {
            "cve_id": cid,
            "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
            "epss_score": r["epss_score"],
            "percentile": r["percentile"],
            "severity": r.get("severity"),
            "cvss_v3_score": r.get("cvss_v3_score"),
            "source": "cache",
        }

    for r in api_results:
        cid = r["cve_id"]
        if cid not in all_scores:
            all_scores[cid] = {
                "cve_id": cid,
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "epss_score": r["epss_score"],
                "percentile": r["percentile"],
                "date_recorded": r.get("date_recorded"),
                "source": "api",
            }

    # Mark not-found CVEs
    for cid in cve_ids:
        if cid not in all_scores:
            all_scores[cid] = {
                "cve_id": cid,
                "url": f"https://nvd.nist.gov/vuln/detail/{cid}",
                "epss_score": None,
                "error": "Score not available",
            }

    return {
        "total_requested": len(cve_ids),
        "total_found": sum(1 for v in all_scores.values() if v.get("epss_score") is not None),
        "scores": [all_scores[cid] for cid in cve_ids],
    }
