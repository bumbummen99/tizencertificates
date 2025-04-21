from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
from typing import Optional
import subprocess
import os
from enum import Enum
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
import certtool
import argparse
import sys
import logging
import webbrowser
from threading import Timer
import json
import requests
import signal


# Get the directory where the script is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Create necessary directories
os.makedirs("certificates", exist_ok=True)


class CertType(str, Enum):
    TV = "VD"
    OTHER = "OTHER"


class TokenStore:
    def __init__(self):
        self.tokens: dict[str, tuple[tuple[str, str], datetime]] = {}

    def store_token(self, state: str, token_data: tuple[str, str]):
        self.tokens[state] = (token_data, datetime.now() + timedelta(minutes=5))

    def get_token(self, state: str) -> Optional[tuple[str, str]]:
        if state not in self.tokens:
            return None
        token_data, expiry = self.tokens[state]
        if datetime.now() > expiry:
            del self.tokens[state]
            return None
        del self.tokens[state]
        return token_data


class ServerConfig:
    def __init__(self):
        self.host: str = "0.0.0.0"
        self.port: int = 8000
        self.callback_path: str = "/auth/callback"
        self.service_id: str = ""
        self.login_url: str = ""
        self.cert_type: CertType = CertType.OTHER
        self.device_id: str = ""
        self.email: str = ""
        self.cert_password: str = ""


def initialize_server(args) -> ServerConfig:
    config = ServerConfig()
    variables = certtool.initialize_server_config()

    if not variables["SERVICE_ID"] or not variables["loginUrl"]:
        raise ValueError("Failed to get SERVICE_ID or loginUrl from certtool")

    config.host = args.host
    config.service_id = variables["SERVICE_ID"]
    config.login_url = variables["loginUrl"]
    config.cert_type = CertType.TV if args.tv else CertType.OTHER
    config.device_id = args.device_id
    config.email = args.email
    config.cert_password = args.cert_password

    # Parse callback path and port from login URL
    parsed_url = urlparse(config.login_url)
    query_params = parse_qs(parsed_url.query)
    if "redirect_uri" in query_params:
        callback_url = urlparse(query_params["redirect_uri"][0])
        if callback_url.port:
            config.port = callback_url.port
        if callback_url.path:
            config.callback_path = callback_url.path

    return config


def generate_certificates(
    cert_type: CertType, device_id: str, email: str, access_token: str, user_id: str, cert_password: str = ""
):
    if not user_id:
        raise Exception("No user ID provided")

    # Setup paths
    base_dir = os.path.abspath(os.path.curdir)
    ca_dir = os.path.join(base_dir, "ca")
    cert_dir = os.path.join(base_dir, "certificates")
    os.makedirs(cert_dir, exist_ok=True)

    # Get CA certificates
    if cert_type == CertType.TV:
        ca_cert = os.path.join(ca_dir, "vd_tizen_dev_author_ca.cer")
        dist_ca_cert = os.path.join(ca_dir, "vd_tizen_dev_public2.crt")
    else:
        ca_cert = os.path.join(ca_dir, "gear_test_author_CA.cer")
        dist_ca_cert = os.path.join(ca_dir, "samsung_tizen_dev_public2.crt")

    if not os.path.exists(ca_cert):
        raise Exception(f"CA certificate not found: {ca_cert}")

    # Change to certificates directory for all operations
    os.chdir(cert_dir)

    # Generate author certificate
    commands = [
        "openssl genrsa -out author.key.pem 2048",
        "openssl rsa -in author.key.pem -outform PEM -pubout -out author.key.pem.pub",
        f'openssl req -new -key author.key.pem -out author.csr -subj "/CN={email}"',
    ]

    # Get author certificate from Samsung
    auth_cmd = (
        f"curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/authors "
        f'-H "Authorization: Bearer {access_token}" '
        f"-F access_token={access_token} "
        f"-F user_id={user_id} "
    )
    if cert_type == CertType.TV:
        auth_cmd += "-F platform=VD "
    auth_cmd += "-F csr=@author.csr --output author.crt"
    commands.append(auth_cmd)

    # Execute commands
    for cmd in commands:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Command failed: {cmd}\nError: {result.stderr}")

    # Concatenate certificates
    with open("author.crt", "rb") as author_cert, open(ca_cert, "rb") as ca_cert_file:
        author_content = author_cert.read()
        ca_content = ca_cert_file.read()

        with open("author-and-ca.crt", "wb") as combined:
            combined.write(author_content)
            if not author_content.endswith(b"\n"):
                combined.write(b"\n")
            combined.write(ca_content)

    # Create author PKCS12
    pkcs12_cmd = (
        f"openssl pkcs12 -export -out author.p12 -inkey author.key.pem "
        f"-in author-and-ca.crt -name usercertificate"
        f" -legacy -passout pass:{cert_password}"
    )

    result = subprocess.run(pkcs12_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {pkcs12_cmd}\nError: {result.stderr}")

    # Generate distributor certificate
    if cert_type == CertType.TV:
        email_part = f"/emailAddress={email}"
    else:
        email_part = ""

    # Handle multiple device IDs
    device_ids = [id.strip() for id in device_id.split(',')]
    san_extension = 'URI:URN:tizen:packageid='
    for dev_id in device_ids:
        if dev_id:  # Only add non-empty device IDs
            san_extension += f',URI:URN:tizen:deviceid={dev_id}'

    dist_commands = [
        "openssl genrsa -out distributor.key.pem 2048",
        "openssl rsa -in distributor.key.pem -outform PEM -pubout -out distributor.key.pem.pub",
        f'openssl req -new -key distributor.key.pem -out distributor.csr -subj "/CN=TizenSDK{email_part}" '
        f'-addext "subjectAltName = {san_extension}"',
    ]

    # Get distributor certificate from Samsung
    dist_cmd = (
        f"curl -v -X POST https://dev.tizen.samsung.com:443/apis/v2/distributors "
        f'-H "Authorization: Bearer {access_token}" '
        f"-F access_token={access_token} "
        f"-F user_id={user_id} "
    )
    if cert_type == CertType.TV:
        dist_cmd += "-F platform=VD "
    dist_cmd += "-F privilege_level=Public -F developer_type=Individual -F csr=@distributor.csr --output distributor.crt"
    dist_commands.append(dist_cmd)

    # Execute commands
    for cmd in dist_commands:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            raise Exception(f"Command failed: {cmd}\nError: {result.stderr}")

    # Concatenate distributor certificates
    with open("distributor.crt", "rb") as dist_cert, open(
        dist_ca_cert, "rb"
    ) as ca_cert_file:
        dist_content = dist_cert.read()
        ca_content = ca_cert_file.read()

        with open("distributor-and-ca.crt", "wb") as combined:
            combined.write(dist_content)
            if not dist_content.endswith(b"\n"):
                combined.write(b"\n")
            combined.write(ca_content)

    # Create distributor PKCS12
    pkcs12_cmd = (
        f"openssl pkcs12 -export -out distributor.p12 -inkey distributor.key.pem "
        f"-in distributor-and-ca.crt -name usercertificate"
        f" -legacy -passout pass:{cert_password}"
    )

    result = subprocess.run(pkcs12_cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0:
        raise Exception(f"Command failed: {pkcs12_cmd}\nError: {result.stderr}")

    # Change back to original directory
    os.chdir(base_dir)


app = FastAPI()
token_store = TokenStore()

# Setup templates with absolute path
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


# Create a function to setup routes that we'll call after config is initialized
def setup_routes():
    # Serve certificate files
    app.mount(
        "/certificates", StaticFiles(directory="certificates"), name="certificates"
    )

    @app.get("/auth/start")
    async def start_auth():
        """Return the login URL instead of redirecting"""
        state = secrets.token_urlsafe(32)
        redirect_uri = f"http://localhost:{config.port}{config.callback_path}"

        # Store the state temporarily with a null token
        token_store.store_token(state, (None, None))

        # Return the URL and state for the client to handle
        return {
            "login_url": config.login_url,
            "service_id": config.service_id,
            "redirect_uri": redirect_uri,
            "state": state,
        }

    @app.api_route(config.callback_path, methods=["GET", "POST"])
    async def auth_callback(request: Request, code: str = None, state: str = None):
        """Handle both GET and POST callbacks from Samsung OAuth"""
        try:
            if request.method == "POST":
                form_data = dict(await request.form())
                code = form_data.get("code")

            if not code:
                raise HTTPException(status_code=400, detail="No code provided")

            try:
                # Parse the response data
                token_data = json.loads(code)
                access_token = token_data.get("access_token")
                user_id = token_data.get("userId")

                if not access_token or not user_id:
                    raise ValueError("Missing required token data")

                # Generate certificates
                generate_certificates(
                    config.cert_type,
                    config.device_id,
                    config.email,
                    access_token,
                    user_id,
                    config.cert_password
                )

                # Get list of generated certificate files
                cert_files = [
                    f for f in os.listdir("certificates") if f.endswith((".p12"))
                ]

                # Get absolute path to certificates directory
                cert_dir = os.path.abspath("certificates")

                # Return HTML completion page
                return templates.TemplateResponse(
                    "completion.html",
                    {
                        "request": request,
                        "certificate_files": sorted(cert_files),
                        "certificates_path": cert_dir,
                        "cert_password": config.cert_password
                    },
                )

            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid code format")
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))

        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/shutdown")
    async def shutdown():
        """Gracefully shutdown the server"""
        os.kill(os.getpid(), signal.SIGTERM)
        return {"message": "Server shutting down"}


def open_browser():
    """Open browser with instructions"""
    try:
        url = f"http://{config.host}:{config.port}/auth/start"
        response = requests.get(url)
        data = response.json()

        auth_url = (
            f"{data['login_url']}?"
            f"serviceID={data['service_id']}&"
            f"actionID=StartOAuth2&"
            f"accessToken=Y&"
            f"redirect_uri={data['redirect_uri']}"
        )

        logging.info(f"Please visit this URL to authenticate:")
        logging.info(auth_url)
        webbrowser.open(config.login_url)
    except Exception as e:
        logging.error(f"Failed to construct URL: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--tv", action="store_true", help="Generate TV certificates")
    parser.add_argument("--device-id", required=True, help="Device ID (comma-separated for multiple IDs)")
    parser.add_argument("--email", required=True, help="Email address")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind the HTTP server to")
    parser.add_argument("--cert-password", required=False, default="", help="Password with which to sign the certificates")
    args = parser.parse_args()

    try:
        config = initialize_server(args)
        setup_routes()  # Setup routes after config is initialized
    except Exception as e:
        logging.error(f"Failed to initialize server: {e}")
        sys.exit(1)

    Timer(1, open_browser).start()
    uvicorn.run(app, host=config.host, port=config.port)
