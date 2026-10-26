import os
import time

from dotenv import load_dotenv
from google import genai
from google.genai import types


load_dotenv()


api_key = os.getenv(
    "GOOGLE_API_KEY"
)

if not api_key:
    raise RuntimeError(
        "GOOGLE_API_KEY is not configured."
    )


client = genai.Client(
    api_key=api_key,
    http_options=types.HttpOptions(
        timeout=90000
    )
)


MODEL_NAME = (
    "gemini-3.5-flash-lite"
)


def generate_response(
    prompt: str
) -> str:

    last_error = None

    for attempt in range(3):

        try:

            response = client.models.generate_content(
                model=MODEL_NAME,
                contents=prompt
            )

            if response.text:
                return response.text

            raise RuntimeError(
                "Gemini returned an empty response."
            )

        except Exception as e:

            last_error = e
            error = str(e)

            if "429" in error:

                raise RuntimeError(
                    "Gemini quota exceeded. "
                    "Wait for the quota window to reset "
                    "before running again."
                )

            if (
                "timeout" in error.lower()
                or "timed out" in error.lower()
                or "readtimeout" in error.lower()
            ):

                if attempt < 2:

                    time.sleep(
                        2 ** attempt
                    )

                    continue

                raise RuntimeError(
                    "Gemini request timed out "
                    "after multiple attempts."
                )

            if "503" in error:

                if attempt < 2:

                    time.sleep(
                        2 ** attempt
                    )

                    continue

                raise RuntimeError(
                    "Gemini service is temporarily "
                    "unavailable after multiple attempts."
                )

            raise

    raise RuntimeError(
        f"Gemini request failed: {last_error}"
    )