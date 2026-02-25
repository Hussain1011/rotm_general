import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok
from rotm_general.run_of_the_mill_general.utils.paging import get_paging_args

@frappe.whitelist(allow_guest=True)
def get_all():
    page, limit, start = get_paging_args()
    stores = frappe.get_all("SB Store",
        filters={"is_active":1},
        fields=["name as store_id","store_name_en","store_name_ar","address","phone",
                "working_hours","is_active","latitude","longitude"],
        start=start, page_length=limit, order_by="modified desc"
    )
    return ok({"stores": stores}, "Stores retrieved successfully.","تم جلب الفروع بنجاح.")  # :contentReference[oaicite:16]{index=16}