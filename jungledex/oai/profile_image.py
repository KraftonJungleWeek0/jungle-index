import os
from openai import OpenAI

def render_image(hobby_list: list, mbti: str, preferred_language: str):
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
    )

    hobby_list_str = ', '.join(hobby_list)
    response = client.images.generate(
        model="dall-e-3",
        prompt=f"This image is a cartoon style a legendary creature which likes {hobby_list_str}, {mbti}, {preferred_language} smiling",
        size="1024x1024",
        quality="standard",
        n=1,
    )
    url = response.data[0].url
    return url