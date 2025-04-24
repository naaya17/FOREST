import openai
import os

from loggers import setup_logger

logger = setup_logger(__name__)

# Set your OpenAI API key here
openai.api_key = os.getenv("OPENAI_API_KEY")
client = openai.Client()

# Define the prompt template
PROMPT_TEMPLATE = """
                    You are a digital forensic analyst reviewing API responses.

                    The following response was captured from an API endpoint: {url}

                    Determine whether this response is forensically relevant. This includes:
                    - User identifiers (e.g., user IDs, usernames, email addresses)
                    - User activity logs (e.g., login/logout, join/leave events)
                    - Personally identifiable information (PII)
                    - Metadata or system messages that indicate user behavior
                    - User configuration, preferences, or account status

                    Do not rely only on keyword matching. Use contextual understanding.
                    Even system messages like "user02 has joined the channel" may be relevant.

                    Respond with **Yes** or **No** and explain your reasoning in **one sentence**.

                    Response Body:
                    {response_body}
                """


# Function to send API response to OpenAI for classification
def analyze_response_with_chatgpt(url, response_body):
    prompt = PROMPT_TEMPLATE.format(url=url, response_body=response_body)
    response = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a digital forensic analyst. "
                    "Your job is to review API responses and decide if they contain forensically relevant user-related data. "
                    "Examples include identifiers, user behavior, or personal info. "
                    "Always respond with Yes or No, followed by a one-sentence reason."
                )
            },
            {"role": "user", "content": prompt}
        ],
        max_tokens=200,
        temperature=0.5
    )
    return response.choices[0].message.content.lower()

def filter_sensitive_responses(url, response_body):
    try:
        logger.info(f"Analyzing API response from: {url}")
        # Analyze the response using ChatGPT
        result = analyze_response_with_chatgpt(url, response_body)
        if "yes" in result:
            logger.info(f"Sensitive data detected for {url}")
            return True  # Sensitive data found
        else:
            return False  # No sensitive data
    except Exception as e:
        logger.error(f"Error analyzing {url}: {e}")
        return False  # Default to non-sensitive if an error occurs