import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok
from rotm_general.run_of_the_mill_general.utils.auth import require_token
from rotm_general.run_of_the_mill_general.utils.paging import get_paging_args

@frappe.whitelist()
def register_token():
    user = require_token()
    data = frappe.parse_json(frappe.request.data or "{}")
    frappe.get_doc({"doctype":"SB FCM Token","owner_user":user,"fcm_token":data.get("fcm_token"),
                    "device_type":data.get("device_type")}).insert()
    return ok({}, "Token registered successfully.","تم تسجيل الرمز بنجاح.")  # :contentReference[oaicite:29]{index=29}

@frappe.whitelist()
def get_all():
    require_token()
    page, limit, start = get_paging_args()
    rows = frappe.get_all("SB Notification", fields=["name as notification_id","title_en","title_ar","body_en","body_ar","type","is_read","creation"],
                          start=start, page_length=limit, order_by="creation desc")
    return ok({"notifications": rows}, "Notifications retrieved.","تم جلب الإشعارات.")  # :contentReference[oaicite:30]{index=30}

@frappe.whitelist()
def mark_read():
    require_token()
    data = frappe.parse_json(frappe.request.data or "{}")
    frappe.db.set_value("SB Notification", data.get("notification_id"), "is_read", 1)
    return ok({}, "Notification marked as read.","تم وضع علامة مقروء.")  # :contentReference[oaicite:31]{index=31}