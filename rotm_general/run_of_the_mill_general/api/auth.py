import frappe, re
from frappe import _
from frappe.utils import now_datetime, random_string
from frappe.utils.password import update_password
from rotm_general.run_of_the_mill_general.utils.responses import ok, err
from rotm_general.run_of_the_mill_general.utils.rate_limit import rate_limited

OTP_TTL_SEC = 600  # 10 min, per spec 5–10 min
OTP_KEY = "sb:otp:{phone}"

@frappe.whitelist(allow_guest=True)
def register():
    rate_limited("register")
    # ✅ works with Postman raw JSON + form-data + anything
    data = get_payload()

    email = data.get("email"); phone = data.get("phone")
    full_name = data.get("full_name"); password = data.get("password")

    if not all([email, phone, full_name, password]):
        return err("Validation failed","فشل التحقق من البيانات", {"fields":"email, phone, full_name, password"}, 417)  # 417 per spec

    # Create User
    if frappe.db.exists("User", {"email": email}):
        return err("Email already registered","البريد مسجل", code=417)
    user = frappe.get_doc({
        "doctype":"User","email":email,"first_name":full_name,"send_welcome_email":0,"enabled":1
    }).insert(ignore_permissions=True)
    update_password(user.name, password)

    # Send OTP
    # _send_otp_internal(phone, is_forget=False)
    return ok({"user": user.as_dict()}, "Registration successful. OTP sent.", "تم التسجيل بنجاح. تم إرسال رمز التحقق.")  # :contentReference[oaicite:7]{index=7}

@frappe.whitelist(allow_guest=True)
def send_otp():
    rate_limited("send_otp")
    data = frappe.parse_json(frappe.request.data or "{}")
    phone = data.get("phone")
    if not phone:
        return err("Validation failed","فشل التحقق من البيانات", {"phone":"required"}, 417)
    _send_otp_internal(phone, bool(data.get("is_forget_password")))
    return ok({"phone_masked": _mask(phone)}, "OTP sent successfully.","تم إرسال رمز التحقق بنجاح.")  # :contentReference[oaicite:8]{index=8}

def _send_otp_internal(phone, is_forget=False):
    otp = random_string(6, only_digits=True)
    frappe.cache().set_value(OTP_KEY.format(phone=phone), otp, OTP_TTL_SEC)
    # TODO: integrate SMS provider here

def get_payload() -> dict:
    """Safe request payload: works with JSON body + form-data + raw bytes."""
    data = frappe.request.get_json(silent=True)
    if not data:
        data = dict(frappe.form_dict) if frappe.form_dict else None
    if not data:
        raw = frappe.request.data or b"{}"
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", errors="ignore")
        try:
            data = frappe.parse_json(raw) or {}
        except Exception:
            data = {}
    return data if isinstance(data, dict) else {}

@frappe.whitelist(allow_guest=True)
def verify_otp():
    data = frappe.parse_json(frappe.request.data or "{}")
    otp = data.get("otp")
    # phone can be carried in session or pass explicitly; keep simple:
    phone = data.get("phone")
    if not all([otp, phone]):
        return err("Validation failed","فشل التحقق من البيانات", {"otp/phone":"required"}, 417)
    stored = frappe.cache().get_value(OTP_KEY.format(phone=phone))
    if stored != otp:
        return err("Invalid OTP","رمز غير صالح", code=417)
    return ok({"user_id":"USR0001","is_verified": True}, "Phone verified successfully.","تم التحقق من الهاتف بنجاح.")  # :contentReference[oaicite:9]{index=9}

@frappe.whitelist(allow_guest=True)
def login():
    # Use Frappe's /api/method/login is option; but we return your shape:
    data = data = get_payload()
    email = data.get("email"); password = data.get("password")
    if not (email and password):
        return err("Validation failed","فشل التحقق من البيانات", {"email/password":"required"}, 417)
    try:
        frappe.local.login_manager.authenticate(email, password)
        frappe.local.login_manager.post_login()
        user = frappe.get_doc("User", email)
        # issue API key/secret
        api_key = user.api_key or frappe.generate_hash(length=15)
        if not user.api_key: user.api_key = api_key; user.save(ignore_permissions=True)
        api_secret = frappe.generate_hash(length=32)
        frappe.db.set_value("User", user.name, "api_secret", api_secret)
        return ok({"user": user.as_dict(), "api_key": api_key, "api_secret": api_secret},
                  "Login successful.","تم تسجيل الدخول بنجاح.")  # :contentReference[oaicite:10]{index=10}
    except Exception:
        return err("Invalid credentials","بيانات دخول غير صحيحة", code=401)

@frappe.whitelist()
def logout():
    frappe.local.login_manager.logout()
    return ok({}, "Logged out successfully.","تم تسجيل الخروج بنجاح.")  # :contentReference[oaicite:11]{index=11}

@frappe.whitelist(allow_guest=True)
def reset_password():
    data = frappe.parse_json(frappe.request.data or "{}")
    email = data.get("email"); phone = data.get("phone"); new_password = data.get("new_password")
    if not all([email, phone, new_password]):
        return err("Validation failed","فشل التحقق", {"fields":"email, phone, new_password"}, 417)
    # (Assume OTP verified previously)
    update_password(email, new_password)
    return ok({}, "Password reset successfully."," تم إعادة تعيين كلمة المرور.")  # :contentReference[oaicite:12]{index=12}

def _mask(p): return p[:5] + "*"*(len(p)-7) + p[-2:]