import hashlib
import hmac
import os
import subprocess
from functools import wraps

from bottle import abort, post, request, run  # type: ignore
from dotenv import load_dotenv
from git import Repo

load_dotenv()

repo = Repo(os.getenv("BLOG_DIR"))


def authorize(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        secret_key = os.getenv("SECRET_KEY")
        signature_header = request.headers.get("X-Hub-Signature-256")  # type: ignore

        verify_signature(request.body.getbuffer(), secret_key, signature_header)  # type: ignore

        return func(*args, **kwargs)

    return wrapper


def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.

    Raise and return 403 if not authorized.

    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        abort(403, "x-hub-signature-256 header is missing!")
    hash_object = hmac.new(secret_token.encode("utf-8"), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        abort(403, "Request signatures didn't match!")


@post("/event_handler", apply=[authorize])
def event_handler():
    event = request.headers.get("X_GITHUB_EVENT")  # type: ignore
    if event == "push":
        origin = repo.remote("origin")
        assert origin.exists()

        origin.fetch()
        origin.pull()

        subprocess.run(["./target/release/yar"], cwd=os.getenv("BLOG_DIR"))


run(host="localhost", port=8080, debug=True)
