import httpx

API_KEY = "shrvbwurgvbwrjhvbwhbv"
API_BASE_URL = "http://127.0.0.1:8000/"

headers = {
    "X-API-Key": API_KEY
}

with httpx.Client() as client:
    response = client.get(f"{API_BASE_URL}", headers=headers)
    print(response.json())
