import openai
import os

# Set your OpenAI API key here
openai.api_key = os.getenv("OPENAI_API_KEY")
client = openai.Client()

# Define the prompt template
PROMPT_TEMPLATE = (
    "The following API response is from an endpoint: {url}. "
    "Determine if the response contains sensitive user-related data such as personal information (e.g., names, emails, phone numbers, addresses, payment details). "
    "Also check for user-related data from services like cloud storage, messaging platforms, or any service that might handle personal or sensitive information. "
    "If yes, provide a brief reason identifying the sensitive data. Otherwise, respond that the data does not appear to be sensitive.\n\n"
    "Response Body: \n{response_body}\n\n"
    "Respond with either 'Yes' or 'No'. Is this response related to user-sensitive data?"
)

# Function to send API response to OpenAI for classification
def analyze_response_with_chatgpt(url, response_body):
    prompt = PROMPT_TEMPLATE.format(url=url, response_body=response_body)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {"role": "system", "content": "You are a helpful assistant that analyzes API responses for sensitive user-related data."},
            {"role": "user", "content": prompt}
        ],
        max_tokens=200,
        temperature=0.5
    )
    return response.choices[0].message.content.lower()

def filter_sensitive_responses(url, response_body):
    try:
        print(f"Analyzing API response from: {url}")
        # Analyze the response using ChatGPT
        result = analyze_response_with_chatgpt(url, response_body)
        if "yes" in result:
            print(f"Sensitive data detected for {url}.")
            return True  # Sensitive data found
        else:
            print(f"No sensitive data found for {url}.")
            return False  # No sensitive data
    except Exception as e:
        print(f"Error analyzing {url}: {e}")
        return False  # Default to non-sensitive if an error occurs