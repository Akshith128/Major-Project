from services.llm_service import generate_response


response = generate_response(
    "Reply with exactly the word OK."
)

print(response)