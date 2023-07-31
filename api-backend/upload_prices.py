import sys
import pandas as pd
import requests
from pydantic import BaseModel
from requests.auth import HTTPBasicAuth

API = "https://api-backend-olsgyubl4a-ew.a.run.app"
# API = "http://localhost:8000"
BATCH_SIZE = 1000


class Credentials(BaseModel):
    client_id: str
    client_secret: str


class AccessToken(BaseModel):
    access_token: str
    token_type: str


def upload_prices(credentials: Credentials, data: pd.DataFrame):
    # Uploads the data in batches to the API's /product-prices endpoint.
    num_batches = (len(data) + BATCH_SIZE - 1) // BATCH_SIZE
    access_token = authenticate(credentials)
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {access_token}",
    }

    for i in range(num_batches):
        start_idx = i * BATCH_SIZE
        end_idx = (i + 1) * BATCH_SIZE
        batch_data = data.iloc[start_idx:end_idx]
        # Convert the batch data to a JSON object
        json_object = convert_to_json_object(batch_data)
        # Make a POST request with the batch data
        response = requests.post(
            f"{API}/product-prices", headers=headers, json=json_object
        )
        response.raise_for_status()
    upload_url = requests.get(f"{API}/validate-product-prices", headers=headers)
    print(f"upload.gcs_url: {upload_url.json().get('gcs_upload').get('url')}")
    print("prices successfully uploaded")


def convert_to_json_object(data):
    """
    Converts the DataFrame to a JSON object with the required structure for uploading.

    Args:
        data (pd.DataFrame): The DataFrame containing the prices data.

    Returns:
        dict: The JSON object with the required structure for uploading to the API.
    """
    grouped_data = data.groupby("product_id")

    json_object = {"products": []}

    for product_id, group in grouped_data:
        product = {
            "product_id": product_id,
            "prices": group[
                ["market", "channel", "price", "valid_from", "valid_until"]
            ].to_dict(orient="records"),
        }

        json_object["products"].append(product)

    return json_object


def authenticate(credentials: Credentials) -> str:
    """
    Authenticates the client using the provided credentials and obtains an access token.

    Args:
        credentials (Credentials): The client credentials for authentication.

    Returns:
        str: The access token obtained from the authentication process.
    """
    auth_resp = requests.post(
        f"{API}/oauth2/v2.0/token",
        auth=(credentials.client_id, credentials.client_secret),
    )
    auth_resp.raise_for_status()
    access_token = auth_resp.json()["access_token"]
    return access_token


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        creds = Credentials.model_validate_json(f.read())
    upload_prices(creds, pd.read_csv(sys.argv[2]))
