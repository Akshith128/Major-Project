import os
import time
from dotenv import load_dotenv
from google import genai

load_dotenv()

client = genai.Client(
    api_key=os.getenv("GOOGLE_API_KEY")
)

MODEL_NAME = "gemini-3.5-flash-lite"


def generate_response(prompt: str) -> str:
    for attempt in range(3):
        try:
            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt
            )

            if response.text:
                return response.text

        except Exception as e:
            if "429" in str(e):
                raise RuntimeError(
                    "Gemini quota exceeded for gemini-3.5-flash-lite."
                )

            if "503" in str(e) and attempt < 2:
                time.sleep(2 ** attempt)
                continue

            raise

    raise RuntimeError("Gemini returned an empty response.")