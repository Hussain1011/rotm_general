import time, frappe
from frappe.utils import now_datetime

def rate_limited(key: str, max_per_min=100):
    r = frappe.cache()
    window = int(time.time() // 60)
    bucket_key = f"rl:{key}:{window}"
    cnt = r.get(bucket_key) or 0
    if int(cnt) >= max_per_min:
        frappe.throw("Rate limit exceeded", exc=frappe.PermissionError)
    r.incr(bucket_key)
    r.expire(bucket_key, 120)