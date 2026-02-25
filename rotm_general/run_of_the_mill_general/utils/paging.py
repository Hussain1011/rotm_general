import frappe

def get_paging_args():
    page = int(frappe.form_dict.get("page", 1))
    limit = int(frappe.form_dict.get("limit", 20))
    start = (page - 1) * limit
    return page, limit, start