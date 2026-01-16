from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii

app = Flask(__name__)

# مفاتيح التشفير
KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

def encrypt_data(plain_text):
    """تشفير البيانات باستخدام AES-CBC"""
    if isinstance(plain_text, str):
        plain_text = bytes.fromhex(plain_text)
    cipher = AES.new(KEY, AES.MODE_CBC, IV)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def encode_id(number):
    """تشفير ID اللاعب"""
    number = int(number)
    encoded_bytes = []
    while True:
        byte = number & 0x7F
        number >>= 7
        if number:
            byte |= 0x80
        encoded_bytes.append(byte)
        if not number:
            break
    return bytes(encoded_bytes).hex()

def get_jwt_token(uid, password):
    """الحصول على JWT باستخدام API المخصص"""
    try:
        response = requests.get(
            f"https://mohamedbaidone123-f1t4.vercel.app//get?uid={uid}&password={password}",
            timeout=10
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, list):
                return data[0].get("token")
            return data.get("token")
        return None
    except Exception as e:
        print(f"Error getting JWT: {str(e)}")
        return None

@app.route('/add/<uid>/<password>/<friend_id>', methods=['GET'])
def add_friend(uid, password, friend_id):
    """إرسال طلب صداقة"""
    jwt_token = get_jwt_token(uid, password)
    if not jwt_token:
        return jsonify({"error": "فشل في الحصول على JWT من API"}), 401
    
    enc_id = encode_id(friend_id)
    payload = f"08a7c4839f1e10{enc_id}1801"
    enc_data = encrypt_data(payload)
    
    try:
        response = requests.post(
            "https://clientbp.ggblueshark.com/RequestAddingFriend",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB52",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            },
            data=bytes.fromhex(enc_data),
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify({
                "status": "success",
                "message": "تم إرسال طلب الصداقة بنجاح",
                "details": {
                    "friend_id": friend_id,
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            })
        else:
            return jsonify({
                "status": "error",
                "message": "فشل في إرسال طلب الصداقة",
                "details": {
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            })
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "حدث خطأ أثناء محاولة إرسال طلب الصداقة",
            "error_details": str(e)
        }), 500

@app.route('/remove/<uid>/<password>/<friend_id>', methods=['GET'])
def remove_friend(uid, password, friend_id):
    """حذف صديق"""
    jwt_token = get_jwt_token(uid, password)
    if not jwt_token:
        return jsonify({"error": "فشل في الحصول على JWT من API"}), 401
    
    enc_id = encode_id(friend_id)
    payload = f"08a7c4839f1e10{enc_id}1802"
    enc_data = encrypt_data(payload)
    
    try:
        response = requests.post(
            "https://clientbp.ggblueshark.com/RemoveFriend",
            headers={
                "Authorization": f"Bearer {jwt_token}",
                "X-Unity-Version": "2018.4.11f1",
                "X-GA": "v1 1",
                "ReleaseVersion": "OB52",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": "Dalvik/2.1.0 (Linux; Android 9)",
                "Connection": "Keep-Alive",
                "Accept-Encoding": "gzip"
            },
            data=bytes.fromhex(enc_data),
            timeout=10
        )
        
        if response.status_code == 200:
            return jsonify({
                "status": "success",
                "message": "تم حذف اللاعب من قائمة الأصدقاء بنجاح",
                "details": {
                    "friend_id": friend_id,
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            })
        else:
            return jsonify({
                "status": "error",
                "message": "فشل في حذف اللاعب",
                "details": {
                    "response_code": response.status_code,
                    "server_response": response.text
                }
            })
            
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": "حدث خطأ أثناء محاولة حذف الصديق",
            "error_details": str(e)
        }), 500

@app.route('/')
def home():
    """الصفحة الرئيسية"""
    return jsonify({
        "status": "نشط",
        "endpoints": {
            "/add/<uid>/<password>/<friend_id>": "إرسال طلب صداقة - يعيد رسالة نجاح عند الإتمام",
            "/remove/<uid>/<password>/<friend_id>": "حذف صديق - يعيد رسالة نجاح عند الإتمام"
        },
        "usage_example": {
            "add_friend": "http://127.0.0.1:5000/add/3831627617/CAC2F2F3E2F28C5F5944D502CD171A8AAF84361CDC483E94955D6981F1CFF3E3/7555887233",
            "remove_friend": "http://127.0.0.1:5000/remove/3831627617/CAC2F2F3E2F28C5F5944D502CD171A8AAF84361CDC483E94955D6981F1CFF3E3/7555887233"
        },
        "note": "يجب استبدال القيم في الأمثلة ببيانات الحساب الفعلية"
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
