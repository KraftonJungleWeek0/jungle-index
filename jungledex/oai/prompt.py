import random


def make_prompt(user_choice_attr: str):

    base_prompt = f"A cartoon-style sad green frog character with big expressive eyes,slightly drooping eyelids,and a melancholic facial expression ,character is dressed in an outfit that reflects their passion for {user_choice_attr}, expressive, and fitting for {user_choice_attr} theme, sitting alone in a white background or doing {user_choice_attr}. The frog has a human-like posture. "
    
    attr_prompt = f"The character has a deep passion for {user_choice_attr}, and the illustration highlights {user_choice_attr}."

    style_prompt = "Clean digital illustration style. High contrast, simple flat colors, internet meme-inspired style."

    return base_prompt + attr_prompt + style_prompt