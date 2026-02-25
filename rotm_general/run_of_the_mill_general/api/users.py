import frappe, json
from frappe.utils import now_datetime
from rotm_general.run_of_the_mill_general.utils.responses import ok, err
from rotm_general.run_of_the_mill_general.utils.auth import require_token
from rotm_general.run_of_the_mill_general.utils.paging import get_paging_args

ORDER_FLOW = ["pending","paid","confirmed","preparing","ready","completed","cancelled","refunded"]  # :contentReference[oaicite:18]{index=18}

def _so_to_payload(so):
    return {
      "order_id": so.name,
      "order_number": so.name,
      "status": so.custom_status or "pending",
      "subtotal": so.total or 0,
      "tax": so.total_taxes_and_charges or 0,
      "total_amount": so.grand_total or 0,
      "currency": so.currency,
      "pickup_date": so.transaction_date,
      "pickup_time": so.get("custom_pickup_time"),
      "notes": so.po_no,  # reuse or custom field
      "payment_status": so.get("custom_payment_status") or "pending",
      "created_at": so.creation
    }

@frappe.whitelist()
def create():
    user = require_token()
    data = frappe.parse_json(frappe.request.data or "{}")
    items = data.get("items") or []
    if not (data.get("store_id") and items):
        return err("Validation failed","فشل التحقق", {"store_id/items":"required"}, 417)

    so = frappe.get_doc({
        "doctype":"Sales Order",
        "customer": _ensure_customer(user),
        "company": frappe.db.get_default("company"),
        "transaction_date": data.get("pickup_date"),
        "delivery_date": data.get("pickup_date"),
        "custom_pickup_time": data.get("pickup_time"),
        "po_no": data.get("notes"),  # temp field for notes or create custom
        "items": [{"item_code": i["product_id"], "qty": i["quantity"]} for i in items],
        "custom_status": "pending",
        "custom_store_id": data.get("store_id"),
        "custom_payment_status": "pending",
    }).insert()
    so.submit()  # optional: or keep draft until paid

    # Create payment intent ref (SkipCash) and send payment_url (placeholder)
    payload = _so_to_payload(so)
    payload.update({"payment_url":"https://skipcash.com/pay/xyz123","payment_reference":"PAY123"})
    return ok({"order": {"name": so.name, "status": "pending"}, "total_amount": so.grand_total,
              "currency": so.currency, "payment_url": payload["payment_url"], "payment_reference": "PAY123"},
              "Order created successfully.","تم إنشاء الطلب بنجاح." )  # :contentReference[oaicite:19]{index=19}

@frappe.whitelist()
def get_details():
    require_token()
    order_id = frappe.form_dict.get("order_id")
    so = frappe.get_doc("Sales Order", order_id)
    items = [{"product_id": it.item_code, "name_en": it.item_name, "quantity": it.qty,
              "unit_price": it.rate, "total_price": it.amount} for it in so.items]
    data = _so_to_payload(so) | {"store": {"store_id": so.get("custom_store_id"), "name_en": ""}, "items": items}
    return ok(data, "Order details retrieved.","تم جلب تفاصيل الطلب.")  # :contentReference[oaicite:20]{index=20}

@frappe.whitelist()
def get_history():
    user = require_token()
    page, limit, start = get_paging_args()
    customer = _ensure_customer(user)
    rows = frappe.get_all("Sales Order", filters={"customer": customer},
            fields=["name","grand_total","currency","transaction_date","creation","custom_status"],
            start=start, page_length=limit, order_by="creation desc")
    out = []
    for r in rows:
        out.append({
          "order_id": r.name, "order_number": r.name, "status": r.custom_status or "pending",
          "total_amount": r.grand_total, "currency": r.currency, "store_name_en": "",
          "store_name_ar": "", "pickup_date": str(r.transaction_date), "created_at": r.creation,
          "items_count": frappe.db.count("Sales Order Item", {"parent": r.name})
        })
    total = frappe.db.count("Sales Order", {"customer": customer})
    return ok({"orders": out, "pagination": {"current_page": page, "total_pages": (total+limit-1)//limit, "total_orders": total}},
              "Order history retrieved.","تم جلب سجل الطلبات.")  # :contentReference[oaicite:21]{index=21}

@frappe.whitelist()
def reorder():
    require_token()
    data = frappe.parse_json(frappe.request.data or "{}")
    src = frappe.get_doc("Sales Order", data.get("original_order_id"))
    data["items"] = [{"product_id": it.item_code, "quantity": it.qty} for it in src.items]
    frappe.form_dict.update(data)
    return create()  # response shape per spec (201) :contentReference[oaicite:22]{index=22}

@frappe.whitelist()
def cancel():
    require_token()
    data = frappe.parse_json(frappe.request.data or "{}")
    so = frappe.get_doc("Sales Order", data.get("order_id"))
    so.db_set("custom_status","cancelled")
    return ok({"order_id": so.name, "status": "cancelled", "refund_status":"pending"},
              "Order cancelled successfully.","تم إلغاء الطلب بنجاح.")  # :contentReference[oaicite:23]{index=23}

def _ensure_customer(user):
    cust = frappe.db.get_value("Customer", {"email_id": user}, "name")
    if cust: return cust
    d = frappe.get_doc({"doctype":"Customer","customer_name":user,"customer_type":"Individual","email_id":user}).insert()
    return d.name