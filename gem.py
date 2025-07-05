import google.generativeai as genai
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini with your API key
genai.configure(api_key=os.getenv('API_KEY'))

# Load the model
model = genai.GenerativeModel("gemini-2.5-flash")

def verify_post_with_gemini(post_content):
    prompt = f"""You are a fact-checking AI assistant. Given the following post content, 
    respond with only `true` if the news seems likely to be true, or `false` if it seems fake. 
    Be concise and do not include explanations.

    Post: "{post_content}"
    Is this news likely true or fake? (Only respond `true` or `false`)
    """
    try:
        response = model.generate_content(prompt)
        verdict = response.text.strip().lower()
        if 'true' in verdict:
            return True
        elif 'false' in verdict:
            return False
    except Exception as e:
        print("Gemini API Error:", e)
    return None  # In case of error
