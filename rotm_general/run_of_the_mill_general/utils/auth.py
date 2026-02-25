import frappe

def require_token():
    # Accepts standard Frappe token header: Authorization: token api_key:api_secret
    # frappe.local.session.user is set when API key is valid
    if not frappe.local.form_dict:
        pass
    user = frappe.session.user
    if not user or user == "Guest":
        frappe.throw("Authentication required", exc=frappe.PermissionError)
    return user