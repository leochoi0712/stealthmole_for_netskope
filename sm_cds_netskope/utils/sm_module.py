import jwt
import requests
import uuid
import datetime
from datetime import timezone


def create_header(access_key, secret_key):
    """
    Creates a JSON web token header
    """
    payload = {
        "access_key": access_key,
        "nonce": str(uuid.uuid4()),
        "iat": int(datetime.datetime.now(timezone.utc).timestamp()),
    }
    jwt_token = jwt.encode(payload, secret_key)
    authorization_token = "Bearer {}".format(jwt_token)
    return {"Authorization": authorization_token}


def search_query(access_key, secret_key, query, start=None):
    server_url = "https://api.stealthmole.com/v2/cds/export"
    params = {"query": query, "limit": 0, "exportType": "json"}

    if start:
        params["start"] = start

    return requests.get(
        server_url, params=params, headers=create_header(access_key, secret_key)
    )


def validate_credentials(access_key, secret_key):
    server_url = "https://api.stealthmole.com/v2/user/quotas"
    return requests.get(server_url, headers=create_header(access_key, secret_key))
