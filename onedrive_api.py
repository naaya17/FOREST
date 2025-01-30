import time
import requests
import json
import os
from dotenv import load_dotenv
from playwright.sync_api import sync_playwright

# Load environment variables
load_dotenv()

# Microsoft Graph API app information
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
TOKEN_DIR = "tokens"

AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
DRIVE_API_URL = "https://graph.microsoft.com/v1.0/me/drive/root/children"

# Create token directory if it does not exist
os.makedirs(TOKEN_DIR, exist_ok=True)

# Token management functions
def get_token_filepath(user_email):
    """Returns the file path for a specific user's token file."""
    safe_email = user_email.replace("@", "_").replace(".", "_")
    return os.path.join(TOKEN_DIR, f"{safe_email}.json")

def save_tokens(user_email, tokens):
    """Saves the access token and refresh token to a JSON file for a specific user."""
    token_path = get_token_filepath(user_email)
    with open(token_path, "w") as f:
        json.dump(tokens, f)

def load_tokens(user_email):
    """Loads the access token and refresh token for a specific user."""
    token_path = get_token_filepath(user_email)
    if os.path.exists(token_path):
        try:
            with open(token_path, "r") as f:
                tokens = json.load(f)
                if "access_token" in tokens and "refresh_token" in tokens:
                    return tokens
        except (json.JSONDecodeError, KeyError):
            print(f"Token file for {user_email} is corrupted. Re-authentication is required.")
            os.remove(token_path)
    return None

# Playwright automation for authentication
def get_auth_code():
    """Uses Playwright to open a browser, log in, and retrieve the authentication code."""
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "scope": "User.Read Files.Read.All offline_access openid profile email",
    }
    auth_url = f"{AUTH_URL}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        page.goto(auth_url)

        print("Complete the Microsoft login and authentication process in the browser.")

        try:
            time.sleep(30)  # Wait for user input
            print("After logging in, copy and paste the 'code' value from the browser URL.")
            auth_code = input("Enter the authentication code: ").strip()
        except Exception as e:
            print(f"Failed to retrieve authentication code: {e}")
            auth_code = None

        browser.close()

        if auth_code:
            print(f"Authentication code retrieved: {auth_code}")
            return auth_code
        else:
            print("Failed to retrieve authentication code. Please try again.")
            return None

# Token retrieval function
def get_tokens():
    """Retrieves the access token and refresh token after Playwright authentication."""
    auth_code = get_auth_code()
    if not auth_code:
        return None, None

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": REDIRECT_URI,
    }
    response = requests.post(TOKEN_URL, data=data)
    response_json = response.json()
    
    if "access_token" in response_json:
        access_token = response_json["access_token"]

        # Retrieve user email
        user_info = requests.get("https://graph.microsoft.com/v1.0/me", headers={"Authorization": f"Bearer {access_token}"})
        if user_info.status_code == 200:
            user_email = user_info.json().get("userPrincipalName")
            print(f"Logged in as: {user_email}")
            save_tokens(user_email, response_json)
            return user_email, response_json
        else:
            print(f"Failed to retrieve user information: {user_info.text}")

    print(f"Failed to obtain access token: {response_json}")
    return None, None

# Refresh token function
def refresh_access_token(user_email, refresh_token):
    """Uses the refresh token to obtain a new access token."""
    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
    }
    response = requests.post(TOKEN_URL, data=data)
    response_json = response.json()

    if "access_token" in response_json:
        print(f"Access token refreshed for {user_email}.")
        save_tokens(user_email, response_json)
        return response_json["access_token"]
    else:
        print(f"Refresh token expired. Re-authentication is required: {response_json}")
        return None

# Function to retrieve OneDrive file list
def get_onedrive_files():
    """Retrieves and displays the list of OneDrive files for a specific user."""
    user_email = input("Enter the Microsoft account email: ").strip()
    tokens = load_tokens(user_email)

    if not tokens:
        print(f"No access token found for {user_email}. Initiating login process.")
        user_email, tokens = get_tokens()
        if not tokens:
            print("Failed to obtain access token. Exiting program.")
            return

    access_token = tokens["access_token"]
    refresh_token = tokens.get("refresh_token")

    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(DRIVE_API_URL, headers=headers)

    if response.status_code == 200:
        files = response.json().get("value", [])
        if not files:
            print("The OneDrive folder is empty.")
        else:
            print(f"OneDrive files for {user_email}:")
            for file in files:
                print(f"  - {file['name']} (ID: {file['id']})")

    elif response.status_code == 401:
        print(f"Access token expired for {user_email}. Attempting to refresh token.")
        new_access_token = refresh_access_token(user_email, refresh_token)
        if new_access_token:
            get_onedrive_files()
        else:
            print(f"Refresh token for {user_email} is also expired. Re-authentication required.")
            os.remove(get_token_filepath(user_email))
            get_onedrive_files()

    else:
        print(f"Error retrieving OneDrive files: {response.status_code}, {response.text}")

# Run the script
if __name__ == "__main__":
    get_onedrive_files()
