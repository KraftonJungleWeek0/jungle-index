from flask import Flask, render_template,jsonify,request
import sys
from dotenv import load_dotenv
from openai import OpenAI
from pymongo import MongoClient
import webbrowser
import urllib.request
import time
import os
import random

app = Flask(__name__,template_folder='jungle-index/templates')

client = MongoClient('localhost', 27017)
db = client.user

load_dotenv()  # .env 파일 열기

@app.route('/')
def hello():
    return render_template('index.html')
def get_random_category():
    random.choice()
    
def make_prompt(attr_list_str):
    #문자열 리스트로 변환 (공백 제거)
    attr_list = [attr.strip() for attr in attr_list_str.split(',') if attr.strip()]
    #selected_attrs = random.sample(attr_list, min(2, len(attr_list))) #attr_list가 2 미만일 경우 전체 사용 최대 2개 무작위 선택

    selected_attr = random.choice(attr_list) if attr_list else None #무작위 1개 attr 뽑는 경우
    print(selected_attr)
    base_prompt = f"A cartoon-style sad green frog character with big expressive eyes,slightly drooping eyelids,and a melancholic facial expression ,character is dressed in an outfit that reflects their passion for {selected_attr}, expressive, and fitting for {selected_attr} theme, sitting alone in a white background or doing {selected_attr}. The frog has a human-like posture. "
    

    if selected_attr:
        attr_prompt = f"The character has a deep passion for {selected_attr}, and the illustration highlights {selected_attr}."
    else:
        attr_prompt = ""

    style_prompt = "Clean digital illustration style. High contrast, simple flat colors, internet meme-inspired style."

    return base_prompt + attr_prompt + style_prompt

@app.route('/render_image', methods=['POST'])
def render_avata_image():
    attrList = request.form.get('attrList_give')
    prompt = make_prompt(attrList)
    img_dest = "./jungle-index/static/"
    start = time.time()  # 파일 생성 시간 확인용

    client = OpenAI(  # api key 설정
        api_key=os.environ.get("OPENAI_API_KEY"),
    )    
    response = client.images.generate(
        model="dall-e-3",
        prompt=prompt,
        size="1024x1024",
        quality="standard",
        n=1,
    )
    
    url = response.data[0].url


    urllib.request.urlretrieve(
        url, img_dest+"result1.jpg")  # url에서 디스크로 파일 다운로드 함수


    end = time.time()

    print(f"총 소요시간 {end-start}초")
    webbrowser.open(response.data[0].url)


    return jsonify({'result':'success','attrList':attrList})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
