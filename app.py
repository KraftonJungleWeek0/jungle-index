import os
import random
import re
from datetime import timedelta

import bcrypt
from dotenv import load_dotenv
from flask import (
    Flask,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
    set_access_cookies,
    unset_jwt_cookies,
)
from pymongo import MongoClient

from jungledex.oai.profile_image import generate_user_profile_image

load_dotenv()  # .env 파일 열기

app = Flask(
    __name__,
    template_folder="jungledex/templates",
    static_folder="jungledex/static",
    static_url_path="/static",
)
# 대카테고리 리스트
category_list = ["취미", "MBTI", "선호 언어"]
# 소카테고리 리스트
hobby_attr_list = [
    "스케이트 보딩",
    "여행",
    "테니스",
    "독서",
    "헬스",
    "게임",
    "드라이브",
    "요리",
    "음악",
    "미술",
    "무술",
    "춤",
    "축구",
    "요가",
    "러닝",
    "코딩",
    "클라이밍",
    "골프",
    "스키",
    "영화",
]
mbti_attr_list = ["E", "I", "S", "N", "T", "F", "J", "P"]
lang_attr_list = [
    "Python",
    "JavaScript",
    "Java",
    "C++",
    "C#",
    "Go",
    "Rust",
    "Typescript",
    "Swift",
]

category_attr_match_dict = {
    "취미": hobby_attr_list,
    "MBTI": mbti_attr_list,
    "선호 언어": lang_attr_list,
}

hobby_emoji_match_dict = {
    "러닝": "🏃‍♂️",
    "독서": "📚",
    "테니스": "🎾",
    "게임": "🎮",
    "헬스": "🏋️‍♀️",
    "클라이밍": "🧗",
    "코딩": "👨‍💻",
    "춤": "💃",
    "무술": "🥊",
    "음악": "🎧",
    "요리": "👩‍🍳",
    "드라이브": "🚙",
    "여행": "✈️",
    "영화": "🍿",
    "요가": "🧘‍♀️",
    "축구": "⚽️",
    "미술": "🎨",
    "스키": "⛷️",
    "스케이트 보딩": "🛹",
    "골프": "⛳️",
}


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


# 토큰이 없거나 헤더에 Authorization 정보가 없을 때
@jwt.unauthorized_loader
def handle_missing_token(error_str):
    return redirect(url_for("unauthorized_page"))


# Access Token 이 만료되었을 때
@jwt.expired_token_loader
def handle_expired_token(jwt_header, jwt_payload):
    return redirect(url_for("unauthorized_page"))


# 유효하지 않은(위조된) 토큰일 때
@jwt.invalid_token_loader
def handle_invalid_token(error_str):
    return redirect(url_for("unauthorized_page"))


@app.route("/")
def hello():
    return render_template("landing.html")


@app.route("/unauthorized")
def unauthorized_page():
    # 401 status code 로 응답
    return render_template("unauthorized.html"), 401


@app.route("/signin")
def signin_page():
    return render_template("signin.html")


@app.route("/signup")
def signup_page():
    return render_template("signup.html")


@app.route("/myprofile")
def profile_page():
    return render_template("myprofile.html")


@app.route("/dashboard")
@jwt_required()  # JWT 필수
def dashboard_page():
    # 1) 토큰에서 현재 사용자 가져오기
    current_user = get_jwt_identity()

    # 2) 현재 사용자의 도감(captured_users) 리스트 불러오기
    user_doc = db.users.find_one({"username": current_user})
    captured_list = user_doc.get("captured_users", [])

    # 3) 본인과 이미 캡처한 유저를 모두 제외하기 위한 리스트
    exclude_list = [current_user] + captured_list

    # 4) 랜덤 속성 선택
    random_big_attr = random.choice(category_list)
    small_attr_list = category_attr_match_dict.get(random_big_attr)
    random_small_attr = random.choice(small_attr_list)

    # 5) 공통 필터: username이 exclude_list에 들어있지 않아야 함
    base_filter = {"username": {"$nin": exclude_list}}

    if random_big_attr == "취미":
        base_filter["hobbies"] = random_small_attr
    elif random_big_attr == "MBTI":
        base_filter["mbti"] = {"$regex": random_small_attr, "$options": "i"}
    else:  # 선호 언어
        base_filter["languages"] = random_small_attr

    # 6) 필터 적용해서 조회
    raw_users = db.users.find(base_filter)

    # 7) 필요한 필드만 뽑아서 새 리스트 생성
    target_attr_users = [
        {
            "username": u["username"],
            "profile_url": u["profile_url"],
            "user_choice": hobby_emoji_match_dict.get(u["user_choice"]),
        }
        for u in raw_users
    ]

    # 8) 본인 정보 조회(프로필 URL 등)
    user = user_doc  # 이미 조회해 뒀으므로 재조회하지 않아도 됩니다.

    return render_template(
        "dashboard.html",
        username=current_user,
        profile_url=user["profile_url"],
        user_choice=user["user_choice"],
        random_big_attr=random_big_attr,
        random_small_attr=random_small_attr,
        target_attr_users=target_attr_users,
    )


@app.route("/api/auth/check", methods=["POST"])
def check_username():
    data = request.get_json() or {}
    username = data.get("username")

    if db.users.find_one({"username": username}):
        return api_response("error", "이미 가입된 사용자입니다."), 409
    else:
        return api_response("success", "사용자명 사용 가능"), 200


@app.route("/api/auth/signup", methods=["POST"])
def signup_api():
    data = request.get_json() or {}
    username = data.get("username")
    raw_password = data.get("password")
    real_name = data.get("real_name")
    about_me = data.get("aboutMe")
    hobbies = data.get("hobbies", [])
    mbti = data.get("mbti")
    languages = data.get("languages")
    user_choice = data.get("user_choice")

    # 비밀번호 해시
    password_bytes = str(raw_password).encode("utf-8")
    hashed_password = bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")

    # 프로필 이미지 생성
    image_url = generate_user_profile_image(user_choice)

    # 사용자 정보 저장
    db.users.insert_one(
        {
            "username": username,
            "password": hashed_password,
            "real_name": real_name,
            "about_me": about_me,
            "hobbies": hobbies,
            "mbti": mbti,
            "languages": languages,
            "profile_url": image_url,
            "user_choice": user_choice,
            "captured_users": [],
        }
    )

    # 토큰 생성 및 응답
    access_token = create_access_token(identity=username)
    resp = api_response("success", "회원가입이 완료되었습니다.", {"username": username})
    resp.status_code = 201
    set_access_cookies(resp, access_token, max_age=900)
    return resp


@app.route("/api/auth/signin", methods=["POST"])
def signin_api():
    data = request.get_json() or {}
    username = data.get("username")
    raw_password = data.get("password")

    # 저장된 비밀번호 조회
    user = db.users.find_one({"username": username})
    if not user:
        return api_response("error", "아이디 또는 비밀번호가 올바르지 않습니다."), 401
    stored_password = user["password"]

    # 비밀번호 검증
    if bcrypt.checkpw(
        str(raw_password).encode("utf-8"), stored_password.encode("utf-8")
    ):
        access_token = create_access_token(identity=username)
        resp = api_response("success", "로그인에 성공했습니다.", {"username": username})
        resp.status_code = 200
        set_access_cookies(resp, access_token, max_age=3600)
        return resp

    return api_response("error", "아이디 또는 비밀번호가 올바르지 않습니다."), 401


@app.route("/api/auth/logout", methods=["POST"])
@jwt_required()
def logout():
    resp = api_response("success", "로그아웃 되었습니다.")
    unset_jwt_cookies(resp)
    resp.status_code = 200
    return resp


@app.route("/api/quiz/<username>", methods=["GET"])
@jwt_required()
def generate_quiz(username):
    user = db.users.find_one({"username": username})
    main = random.choice(category_list)
    sub = random.choice(category_attr_match_dict[main])

    # 정답 판정
    if main == "취미":
        answer = sub in user.get("hobbies", [])
    elif main == "MBTI":
        answer = bool(re.search(sub, user.get("mbti", ""), re.IGNORECASE))
    else:  # 선호 언어
        answer = sub == user.get("languages")

    quiz_str = f"{username}몬의 {main} 중 하나가 바로 {sub}이에요."
    return (
        api_response(
            "success",
            "Quiz generated",
            {
                "mainAttr": main,
                "subAttr": sub,
                "quiz_string": quiz_str,
                "quiz_answer": answer,
            },
        ),
        200,
    )


@app.route("/api/capture/<target_username>", methods=["POST"])
@jwt_required()
def capture_user(target_username):
    current = get_jwt_identity()
    # 현재 유저의 captured_users 배열에 중복 없이 추가
    db.users.update_one(
        {"username": current}, {"$addToSet": {"captured_users": target_username}}
    )
    return api_response("success", f"{target_username}몬이 도감에 등록되었습니다."), 200


@app.route("/user/<username>")
@jwt_required()
def user_profile(username):
    # 토큰에서 사용자 아이디(또는 username)를 꺼내서 템플릿에 전달
    current_user = get_jwt_identity()
    user = db.users.find_one({"username": current_user})
    doc = db.users.find_one({"username": username})

    return render_template("user.html", user=user, another_user=doc)


@app.route("/my")
@jwt_required()  # JWT 필수
def my_profile():
    current_user = get_jwt_identity()
    user = db.users.find_one({"username": current_user})
    if user:
        user_list = user["captured_users"]
    else:
        user_list = []
    doc_list = []
    for i in user_list:
        doc_list.append(db.users.find_one({"username": i}))
    # user_list는 도감에 등록된 user를 받아와야 해서 추후에 가능 일단 막바로

    return render_template("myprofile.html", user=user, user_list=doc_list)


if __name__ == "__main__":
    app.run(debug=True)
