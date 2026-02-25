import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok

@frappe.whitelist(allow_guest=True)
def get_banners():
    rows = frappe.get_all("SB Banner",
        fields=["banner as banner_id","title_en","title_ar","image_url","link_type","link_id",
                "display_order","valid_until"],
        order_by="display_order asc, modified desc")
    return ok({"banners": rows}, "Banners retrieved successfully.","تم جلب البانرات بنجاح.")  # :contentReference[oaicite:32]{index=32}