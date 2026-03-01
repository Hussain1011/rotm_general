import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok

@frappe.whitelist(allow_guest=True)
def get_app_config():
    return ok({
        "app_version":"1.0.0","min_order_amount":20.00,"currency":"SAR","tax_rate":15,
        "support_phone":"+966112345678","support_email":"support@smoothiebar.com",
        "terms_url":"https://smoothiebar.com/terms","privacy_url":"https://smoothiebar.com/privacy"
    }, "Configuration retrieved.","تم جلب الإعدادات.")  # :contentReference[oaicite:33]{index=33}