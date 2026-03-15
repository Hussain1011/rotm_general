import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok
from rotm_general.run_of_the_mill_general.utils.paging import get_paging_args


def _parse_latlong(latlong):
    if not latlong:
        return None, None

    text = str(latlong).strip()
    if not text:
        return None, None

    normalized = text.replace(" ", "")
    for separator in [",", "|"]:
        if separator in normalized:
            parts = normalized.split(separator, 1)
            try:
                return float(parts[0]), float(parts[1])
            except (TypeError, ValueError):
                return None, None

    return None, None

@frappe.whitelist(allow_guest=True)
def get_all():
    page, limit, start = get_paging_args()
    rows = frappe.get_all("SB Store",
        filters={"is_active":1},
        fields=["name", "name_en", "name_ar", "phone", "hours", "latlong", "is_active"],
        start=start, page_length=limit, order_by="modified desc"
    )

    stores = []
    for row in rows:
        latitude, longitude = _parse_latlong(row.get("latlong"))
        stores.append({
            "store_id": row.get("name"),
            "store_name_en": row.get("name_en"),
            "store_name_ar": row.get("name_ar"),
            "address": "",
            "phone": row.get("phone"),
            "working_hours": row.get("hours"),
            "is_active": row.get("is_active"),
            "latitude": latitude,
            "longitude": longitude,
        })

    return ok({"stores": stores}, "Stores retrieved successfully.","تم جلب الفروع بنجاح.")  # :contentReference[oaicite:16]{index=16}