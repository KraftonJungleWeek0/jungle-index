import os
from openai import OpenAI

from jungledex.oai.prompt import make_prompt

def generate_user_profile_image(user_choice: str):
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
    )

    prompt = make_prompt(user_choice)
    
    response = client.images.generate(
        model="dall-e-3",
        prompt=prompt,
        size="1024x1024",
        n=1,
        quality="standard"
    )

    url = response.data[0].url

    return url