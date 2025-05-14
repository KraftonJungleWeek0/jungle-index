import os
from openai import OpenAI


def generate_user_profile_image(user_choice: str, illustration: str = "pokemon"):
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
    )

    prompt = f"""
        Create a medium-poly 3D collectible-monster character in a `{illustration}` style, cute game-art (optimized for fast generation):
        - Composition: The character should be prominently displayed without any circular frame or border. However, maintain natural, rounded, and smooth shapes for a cute and lively appearance.
        - Style: The character must have a **cute and adorable appearance**, with big round eyes, a friendly facial expression, and soft, rounded body shapes. Avoid any elements that make the character look intimidating, aggressive, or too mechanical.
        - Hobby Representation: The character should be actively engaged in `{user_choice}`, clearly showcasing an action or behavior related to it. For example, lifting dumbbells, stretching, or using a jump rope.
        - Hobby Iconography: Integrate `{user_choice}` elements directly into the character's design (ears, tail, arms, or accessories) to further emphasize the theme.
        - Strictly No Text or Logos: Absolutely no text, letters, numbers, symbols, or logos should be present anywhere in the image, including on objects, the character's body, or the background.
        - Visual Clarity: Ensure that `{user_choice}` is instantly recognizable, with all forms and accessories focused solely on the hobby.
        - Natural Form: Use smooth, organic shapes with soft curves to maintain a friendly and charming appearance. Avoid rigid or geometric forms.
        - Lighting & Shading: Use soft shadows for shape separation, making details stand out clearly.
        - Background: Use a solid or gradient background to enhance the visibility of hobby elements, but avoid any circular background shapes.
    """

    response = client.images.generate(
        model="dall-e-3",
        prompt=prompt,
        n=1,
    )

    url = response.data[0].url
    return url