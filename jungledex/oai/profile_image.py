import os

from openai import OpenAI


def generate_user_profile_image(
    user_choice_hobby: str, style: str = "pokemon animation"
):
    client = OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY"),
    )

    prompt = f"""
    Create a medium-poly 3D collectible-monster character in a `{style}` style, cute game-art (optimized for fast generation):
    - Single Character: **The illustration must feature exactly one character.** This is extremely important—begin your design process with this requirement.
    - Composition: The character should be prominently displayed without any circular frame or border. Maintain natural, rounded, and smooth shapes for a cute and lively appearance.
    - Style: The character must have a cute and adorable appearance, with a friendly facial expression and soft, rounded body shapes. Avoid anything intimidating, aggressive, or too mechanical.
    - Eye Size: Do not draw the character’s eyes too large; overly large eyes can look unsettling or “creepy” to the viewer.
    - Hobby Representation: The character should be actively engaged in `{user_choice_hobby}`, clearly showcasing an action or behavior related to it.
    - When depicting the hobby, there must be exactly one object representing the hobby.
    - Hobby Iconography: Integrate `{user_choice_hobby}` elements directly into the character's design (ears, tail, arms, or accessories) to emphasize the theme.
    - Strictly No Text or Logos: Absolutely no text, letters, numbers, symbols, or logos anywhere in the image.
    - Conditional Hobby Details:
    - If the hobby is **game**, include a game console controller.
    - If the hobby is **travel**, have the character wear a travel backpack and look like an explorer.
    - If the hobby is **exercise**, show the character holding a barbell.
    - If the hobby is **reading**, show the character holding a book.
    - If the hobby is **movie**, depict the character clearly watching a movie (e.g., holding popcorn or looking at a screen).
    - If the hobby is **drive**, depict the character driving or seated in a car.
    - Visual Clarity: Ensure the `{user_choice_hobby}` element is instantly recognizable, with all forms and accessories focused solely on the hobby.
    - Natural Form: Use smooth, organic shapes with soft curves for a friendly, charming look. Avoid rigid or geometric forms.
    - Lighting & Shading: Use soft shadows for shape separation and clear detail.
    - Background: Use a solid or gradient background to enhance visibility of the hobby elements, but avoid circular shapes.
    """

    response = client.images.generate(
        model="dall-e-3",
        prompt=prompt,
        n=1,
    )

    url = response.data[0].url
    return url
