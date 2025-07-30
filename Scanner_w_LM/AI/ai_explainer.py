import openai
import os
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def explain_with_ai(title, severity, description):
    response = openai.ChatCompletion.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": "You're a cybersecurity analyst. Explain this vulnerability in clear and actionable terms.",
            },
            {
                "role": "user",
                "content": f"Title: {title}\nSeverity: {severity}\nDescription: {description}",
            },
        ],
    )
    return response["choices"][0]["message"]["content"]
