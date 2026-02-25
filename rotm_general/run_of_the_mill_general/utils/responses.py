import frappe

def ok(data=None, men="Operation completed successfully.", mar="تمت العملية بنجاح."):
    return {"status": "success", "message_en": men, "message_ar": mar, "data": data or {}}

def err(men="Error", mar="خطأ", errors=None, code=400):
    frappe.local.response.http_status_code = code
    return {"status": "error", "message_en": men, "message_ar": mar, "errors": errors or {}, "code": code}