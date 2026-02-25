import frappe
from rotm_general.run_of_the_mill_general.utils.responses import ok
from rotm_general.run_of_the_mill_general.utils.paging import get_paging_args

@frappe.whitelist(allow_guest=True)
def get_items():
    # ?store_name=STR001 — optional filter
    store = frappe.form_dict.get("store_name")
    # Categories = Item Group; Items = Item with is_sales_item=1
    cat_rows = frappe.get_all("Item Group", filters={"is_group":0},
        fields=["name as category_id","item_group_name as name_en"])  # add translations via custom fields name_ar
    result = []
    for c in cat_rows:
        items = frappe.get_all("Item", filters={"item_group": c["category_id"], "disabled":0, "is_sales_item":1},
            fields=["name as product_id","item_name as name_en","image as image_url","standard_rate as price","stock_uom"])
        # add extra fields (name_ar, calories, protein_g, price_list_rate, add-ons) via custom fields
        result.append({**c, "items": items})
    return ok({"categories": result}, "Categories retrieved successfully.","تم جلب الفئات بنجاح.")  # :contentReference[oaicite:17]{index=17}