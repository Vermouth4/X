from fastapi import FastAPI, HTTPException, UploadFile, File, Form, Header, Request
from pydantic import EmailStr
import mysql.connector
from passlib.hash import bcrypt
import re
import uvicorn
import base64
from fastapi.middleware.cors import CORSMiddleware
import random
import string
import time
from datetime import datetime
from fastapi import Body
app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

db_config = {
    "host": "127.0.0.1",
    "user": "root",
    "password": "",
    "database": "deepweb_users"
}

db = mysql.connector.connect(**db_config)

sessions = {}
ip_register_cache = {}
submission_cache = set()

def generate_session_token():
    prefix = "FXFCAJ"
    suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=20))
    return prefix + suffix

def get_client_ip(request: Request):
    return request.client.host

@app.on_event("startup")
def startup():
    cursor = db.cursor()
    cursor.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS status ENUM('normal', 'scam', 'verified') DEFAULT 'normal'")
    db.commit()
    cursor.close()

@app.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    email: EmailStr = Form(...),
    password: str = Form(...),
    avatar: UploadFile = File(None)
):
    client_ip = get_client_ip(request)
    current_time = time.time()
    if client_ip in ip_register_cache:
        if current_time - ip_register_cache[client_ip] < 10:
            raise HTTPException(status_code=429, detail="Too many requests from this IP")
    ip_register_cache[client_ip] = current_time

    username = username.strip()
    email = email.strip()
    password = password.strip()

    if not re.fullmatch(r"^[a-zA-Z0-9_]{5,12}$", username):
        raise HTTPException(status_code=400, detail="Invalid username")

    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE username=%s OR email=%s", (username, email))
    if cursor.fetchone():
        cursor.close()
        raise HTTPException(status_code=409, detail="Username or Email already exists")
    cursor.close()

    avatar_bytes = await avatar.read() if avatar else None
    hashed = bcrypt.hash(password)

    cursor = db.cursor()
    cursor.execute(
        "INSERT INTO users (username, email, password, avatar, status) VALUES (%s, %s, %s, %s, 'normal')",
        (username, email, hashed, avatar_bytes)
    )
    db.commit()
    cursor.close()

    return {"status": True, "message": "Account created"}

@app.post("/login")
def login(identity: str = Form(...), password: str = Form(...)):
    identity = identity.strip()
    password = password.strip()

    cursor = db.cursor(dictionary=True)
    if "@" in identity:
        cursor.execute("SELECT * FROM users WHERE email=%s", (identity,))
    else:
        cursor.execute("SELECT * FROM users WHERE username=%s", (identity,))
    user = cursor.fetchone()
    cursor.close()

    if not user or not bcrypt.verify(password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    avatar_base64 = None
    if user["avatar"]:
        data = user["avatar"]
        if isinstance(data, str):
            data = data.encode("utf-8")
        avatar_base64 = base64.b64encode(data).decode("utf-8")

    session_token = generate_session_token()
    sessions[session_token] = user["id"]

    return {
        "status": True,
        "session": session_token,
        "user": {
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "avatar": avatar_base64,
            "status": user.get("status", "normal")
        }
    }

def validate_session(session: str):
    if not session or session not in sessions:
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

@app.get("/users")
def list_users(session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, username, avatar, status FROM users")
    users = cursor.fetchall()
    cursor.close()

    result = []
    for user in users:
        avatar_base64 = None
        if user["avatar"]:
            data = user["avatar"]
            if isinstance(data, str):
                data = data.encode("utf-8")
            avatar_base64 = base64.b64encode(data).decode("utf-8")
        result.append({"id": user["id"], "username": user["username"], "avatar": avatar_base64, "status": user["status"]})

    return {"status": True, "users": result}

@app.get("/categories")
def get_categories(session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, name FROM categories")
    categories = cursor.fetchall()
    cursor.close()

    return {"status": True, "categories": categories}

@app.get("/products/{category_id}")
def get_products_by_category(category_id: int, session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT id, name, description, price, image FROM products WHERE category_id = %s",
        (category_id,)
    )
    products = cursor.fetchall()
    cursor.close()

    if not products:
        raise HTTPException(status_code=404, detail="No products found for this category")

    for product in products:
        if product["image"]:
            product["image"] = base64.b64encode(product["image"]).decode("utf-8")
        else:
            product["image"] = None

    return {"status": True, "products": products}

@app.post("/product/add")
async def add_product(
    request: Request,
    category_id: int = Form(...),
    name: str = Form(...),
    description: str = Form(None),
    price: float = Form(None),
    image: UploadFile = File(...),
    session: str = Header(None)
):
    validate_session(session)

    uid = f"{sessions[session]}-{category_id}-{name}"
    if uid in submission_cache:
        raise HTTPException(status_code=429, detail="Duplicate submission detected")
    submission_cache.add(uid)

    image_bytes = await image.read()
    if not image_bytes:
        raise HTTPException(status_code=400, detail="Image file is required")

    try:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO products (category_id, name, description, price, image) VALUES (%s, %s, %s, %s, %s)",
            (category_id, name, description, price, image_bytes)
        )
        db.commit()
        cursor.close()
    except Exception as e:
        submission_cache.discard(uid)
        raise HTTPException(status_code=500, detail=f"Failed to add product: {str(e)}")

    return {"status": True, "message": "Product added successfully"}

@app.get("/reviews")
def get_all_reviews(session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT reviews.id, reviews.product_id, reviews.user_id, reviews.rating, reviews.comment, reviews.created_at, users.username, users.avatar
        FROM reviews
        JOIN users ON reviews.user_id = users.id
    """)
    reviews = cursor.fetchall()
    cursor.close()

    for review in reviews:
        avatar_base64 = None
        if review["avatar"]:
            data = review["avatar"]
            if isinstance(data, str):
                data = data.encode("utf-8")
            avatar_base64 = base64.b64encode(data).decode("utf-8")
        review["avatar"] = avatar_base64

    return {"status": True, "reviews": reviews}

@app.get("/reviews/product/{product_id}")
def get_reviews_by_product(product_id: int, session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute("""
        SELECT reviews.id, reviews.product_id, reviews.user_id, reviews.rating, reviews.comment, reviews.created_at, users.username, users.avatar
        FROM reviews
        JOIN users ON reviews.user_id = users.id
        WHERE reviews.product_id = %s
    """, (product_id,))
    reviews = cursor.fetchall()
    cursor.close()

    for review in reviews:
        avatar_base64 = None
        if review["avatar"]:
            data = review["avatar"]
            if isinstance(data, str):
                data = data.encode("utf-8")
            avatar_base64 = base64.b64encode(data).decode("utf-8")
        review["avatar"] = avatar_base64

    return {"status": True, "reviews": reviews}

@app.post("/reviews/add")
async def add_review(
    product_id: int = Form(...),
    user_id: int = Form(...),
    rating: int = Form(...),
    comment: str = Form(""),
    session: str = Header(None)
):
    validate_session(session)

    if rating < 1 or rating > 5:
        raise HTTPException(status_code=400, detail="Rating must be between 1 and 5")

    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    try:
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO reviews (product_id, user_id, rating, comment, created_at) VALUES (%s, %s, %s, %s, %s)",
            (product_id, user_id, rating, comment, created_at)
        )
        db.commit()
        cursor.close()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to add review: {str(e)}")

    return {"status": True, "message": "Review added successfully"}

@app.post("/admin/user/status")
async def set_user_status(request: Request, session: str = Header(None)):
    if not session or session not in sessions:
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    body = await request.json()
    username = body.get("username")
    status = body.get("status")

    if not username or not status:
        raise HTTPException(status_code=400, detail="Missing 'username' or 'status'")

    user_id = sessions[session]
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT username, role FROM users WHERE id = %s", (user_id,))
    current_user = cursor.fetchone()

    if not current_user:
        cursor.close()
        raise HTTPException(status_code=401, detail="Session user not found")

    if current_user.get("role") != "admin":
        cursor.close()
        raise HTTPException(status_code=403, detail="Permission denied")

    if status not in ["normal", "scam", "verified"]:
        cursor.close()
        raise HTTPException(status_code=400, detail="Invalid status value")

    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    target_user = cursor.fetchone()

    if not target_user:
        cursor.close()
        raise HTTPException(status_code=404, detail="Target user not found")

    cursor.execute("UPDATE users SET status = %s WHERE username = %s", (status, username))
    db.commit()
    cursor.close()

    return {"status": True, "message": f"User '{username}' status updated to '{status}'"}
@app.get("/profile/{username}")
def get_profile(username: str, session: str = Header(None)):
    validate_session(session)

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, username, avatar, status FROM users WHERE username = %s", (username,))
    user = cursor.fetchone()
    cursor.close()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    avatar_base64 = None
    if user["avatar"]:
        data = user["avatar"]
        if isinstance(data, str):
            data = data.encode("utf-8")
        avatar_base64 = base64.b64encode(data).decode("utf-8")

    return {
    "status": True,
    "user": {
        "id": user["id"],
        "username": user["username"],
        "status": user["status"],
        "avatar": avatar_base64
    }
    }
@app.post("/conversations/open")
def open_conversation(
    user1_username: str = Body(...),
    user2_username: str = Body(...),
    session: str = Header(...)
):
    validate_session(session)

    if user1_username == user2_username:
        raise HTTPException(status_code=400, detail="Cannot open conversation with yourself")

    cursor = db.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM users WHERE username = %s", (user1_username,))
        user1 = cursor.fetchone()
        if not user1:
            raise HTTPException(status_code=404, detail=f"User '{user1_username}' not found")

        cursor.execute("SELECT id FROM users WHERE username = %s", (user2_username,))
        user2 = cursor.fetchone()
        if not user2:
            raise HTTPException(status_code=404, detail=f"User '{user2_username}' not found")

        user1_id = user1["id"]
        user2_id = user2["id"]

        user_min = min(user1_id, user2_id)
        user_max = max(user1_id, user2_id)

        cursor.execute(
            "SELECT * FROM chats WHERE user_min = %s AND user_max = %s",
            (user_min, user_max)
        )
        conversation = cursor.fetchone()

        if conversation:
            return {"status": True, "message": "Conversation already exists", "conversation": conversation}

        cursor.execute(
            "INSERT INTO chats (user1_id, user2_id, user_min, user_max, created_at) VALUES (%s, %s, %s, %s, NOW())",
            (user1_id, user2_id, user_min, user_max)
        )
        db.commit()

        cursor.execute(
            "SELECT * FROM chats WHERE user_min = %s AND user_max = %s",
            (user_min, user_max)
        )
        new_conversation = cursor.fetchone()

        return {"status": True, "message": "Conversation created", "conversation": new_conversation}
    finally:
        cursor.close()
@app.post("/startchat/{chat_id}/send-message")
def send_message(
    chat_id: int,
    content: str = Body(None),
    image_url: str = Body(None),
    session: str = Header(None)
):
    validate_session(session)
    sender_id = sessions[session]

    if not content and not image_url:
        raise HTTPException(status_code=400, detail="Either content or image_url must be provided")

    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM chats WHERE id = %s", (chat_id,))
    conversation = cursor.fetchone()
    if not conversation:
        cursor.close()
        raise HTTPException(status_code=404, detail="Conversation not found")

    if sender_id not in (conversation["user1_id"], conversation["user2_id"]):
        cursor.close()
        raise HTTPException(status_code=403, detail="You are not part of this conversation")

    import uuid
    from datetime import datetime

    message_id = str(uuid.uuid4())
    created_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute(
        "INSERT INTO messages (id, chat_id, sender_id, content, image_url, created_at) VALUES (%s, %s, %s, %s, %s, %s)",
        (message_id, chat_id, sender_id, content, image_url, created_at)
    )
    db.commit()
    cursor.close()

    return {"status": True, "message": "Message sent successfully", "message_id": message_id}
@app.get("/conversations/get")
def get_conversation(
    user1_username: str,
    user2_username: str,
    session: str = Header(None)
):
    # تحقق من صلاحية الجلسة
    if not session or session not in sessions:
        raise HTTPException(status_code=401, detail="Invalid or missing session token")

    cursor = db.cursor(dictionary=True)

    # جلب id المستخدم الأول
    cursor.execute("SELECT id FROM users WHERE username = %s", (user1_username,))
    user1 = cursor.fetchone()
    if not user1:
        cursor.close()
        raise HTTPException(status_code=404, detail=f"User '{user1_username}' not found")

    # جلب id المستخدم الثاني
    cursor.execute("SELECT id FROM users WHERE username = %s", (user2_username,))
    user2 = cursor.fetchone()
    if not user2:
        cursor.close()
        raise HTTPException(status_code=404, detail=f"User '{user2_username}' not found")

    user1_id = user1["id"]
    user2_id = user2["id"]

    user_min = min(user1_id, user2_id)
    user_max = max(user1_id, user2_id)

    # جلب المحادثة حسب ترتيب المستخدمين
    cursor.execute(
        "SELECT * FROM chats WHERE user_min = %s AND user_max = %s",
        (user_min, user_max)
    )
    conversation = cursor.fetchone()

    if not conversation:
        cursor.close()
        raise HTTPException(status_code=404, detail="Conversation not found")

    conversation_id = conversation["id"]

    # جلب كل الرسائل المرتبطة بالمحادثة مرتبة زمنياً
    cursor.execute(
        "SELECT sender_id, message, timestamp FROM messages WHERE chat_id = %s ORDER BY timestamp ASC",
        (conversation_id,)
    )
    messages = cursor.fetchall()
    cursor.close()

    # صياغة الرسائل في قائمة مرتبة
    messages_list = []
    for msg in messages:
        messages_list.append({
            "sender_id": msg["sender_id"],
            "message": msg["message"],
            "timestamp": msg["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(msg["timestamp"], "strftime") else str(msg["timestamp"])
        })

    return {
        "status": True,
        "conversation": {
            "chat_id": conversation_id,
            "user_min": user_min,
            "user_max": user_max,
            "messages": messages_list
        }
    }


if __name__ == "__main__":
    print("API running at: http://127.0.0.1:8000")
    uvicorn.run("px:app", host="127.0.0.1", port=8000, reload=True)
