from flask import Flask, jsonify, request
from dotenv import load_dotenv
from openai import OpenAI
from pymongo import MongoClient
import os
from datetime import timedelta
from flask import Flask, jsonify, make_response, request
from pymongo import MongoClient
import bcrypt
from dotenv import load_dotenv
import os
from jungledex.oai.profile_image import generate_user_profile_image

from flask_jwt_extended import (
    set_access_cookies, create_access_token,
    get_jwt_identity, jwt_required,
    JWTManager, unset_jwt_cookies
)


load_dotenv()  # .env 파일 열기

app = Flask(__name__,template_folder='jungle-index/templates')
    
def api_response(status: str, message: str, data: dict = None):
    payload = {"status": status, "message": message}
    if data is not None:
        payload["data"] = data
    return make_response(jsonify(payload))

# Flask-JWT-Extended 설정
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET")
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_COOKIE_SECURE"] = False
# CSRF 보호 비활성화 (테스트/내부 API용)
app.config["JWT_COOKIE_CSRF_PROTECT"] = False
# Access Token 만료 시간 설정
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)

jwt = JWTManager(app)

# MongoDB 연결
mongo_uri = os.getenv("MONGO_URI")
client = MongoClient(mongo_uri)
db = client.jungleindex

@app.route('/')
def hello():
    return 'Hello, World!'

@app.route("/auth/signup", methods=["POST"])
def signup():
    data = request.get_json() or {}
    username = data.get('username')

    if db.users.find_one({'username': username}):
        return api_response("error", "이미 가입된 사용자입니다."), 409

    raw_password = data.get('password')
    simple_description = data.get('simple_description')
    
    hobby_list = data.get('hobby_list', [])
    mbti = data.get('mbti')
    preferred_language = data.get('preferred_language')
    long_description = data.get('long_description')

    user_choice = data.get('user_choice')

    # 비밀번호 해시
    password_bytes = str(raw_password).encode('utf-8')
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

    # 프로필 이미지 생성
    image_url = generate_user_profile_image(user_choice)

    # 사용자 정보 저장
    db.users.insert_one({
        'username': username,
        'password': hashed_password,
        'simple_description': simple_description,
        'hobby_list': hobby_list,
        'mbti': mbti,
        'preferred_language': preferred_language,
        'long_description': long_description,
        'profile_url': image_url
    })

    # 토큰 생성 및 응답
    access_token = create_access_token(identity=username)
    resp = api_response("success", "회원가입이 완료되었습니다.", {"username": username})
    resp.status_code = 201
    set_access_cookies(resp, access_token, max_age=900)
    return resp

@app.route("/auth/signin", methods=["POST"])
def signin():
    data = request.get_json() or {}
    username = data.get('username')
    raw_password = data.get('password')

    # 저장된 비밀번호 조회
    user = db.users.find_one({'username': username})
    if not user:
        return api_response("error", "아이디 또는 비밀번호가 올바르지 않습니다."), 401
    stored_password = user['password']

    # 비밀번호 검증
    if bcrypt.checkpw(str(raw_password).encode('utf-8'), stored_password.encode('utf-8')):
        access_token = create_access_token(identity=username)
        resp = api_response("success", "로그인에 성공했습니다.", {"username": username})
        resp.status_code = 200
        set_access_cookies(resp, access_token, max_age=3600)
        return resp

    return api_response("error", "아이디 또는 비밀번호가 올바르지 않습니다."), 401

@app.route("/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    resp = api_response("success", "로그아웃 되었습니다.")
    unset_jwt_cookies(resp)
    resp.status_code = 200
    return resp

@app.route("/home", methods=["GET"])
@jwt_required()
def home():
    current_user = get_jwt_identity()
    resp = api_response("success", "홈 정보 조회에 성공했습니다.", {"username": current_user})
    resp.status_code = 200
    return resp

if __name__ == '__main__':
    app.run(debug=True)
