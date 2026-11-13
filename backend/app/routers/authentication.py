import hmac

from fastapi import APIRouter, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field

from app.auth import DemoAuth, SESSION_COOKIE, verify_password

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


def _auth(request: Request) -> DemoAuth | None:
    return getattr(request.app.state, "demo_auth", None)


@router.get("/session")
def session_status(request: Request, response: Response) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    if request.app.state.auth_mode != "demo":
        return {"auth_required": False, "authenticated": True, "username": "Local analyst"}
    auth = _auth(request)
    session = auth.get_session(request.cookies.get(SESSION_COOKIE))
    if session is None:
        if request.cookies.get(SESSION_COOKIE):
            auth.clear_cookie(response)
        return {"auth_required": True, "authenticated": False}
    return {
        "auth_required": True,
        "authenticated": True,
        "username": session.username,
        "csrf_token": session.csrf_token,
        "expires_in": max(0, int(session.expires_at - auth.clock())),
    }


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, object]:
    response.headers["Cache-Control"] = "no-store"
    if request.app.state.auth_mode != "demo":
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Authentication is not enabled.")
    auth = _auth(request)
    if not auth.origin_allowed(request.headers.get("origin")):
        raise HTTPException(status_code=403, detail="Request origin is not allowed.")
    peer = request.client.host if request.client else "unknown"
    if not auth.allow_login_attempt(peer):
        raise HTTPException(
            status_code=429,
            detail="Unable to sign in right now. Try again later.",
            headers={"Retry-After": str(auth.window)},
        )

    password_matches = verify_password(payload.password, auth.password_hash)
    username_matches = hmac.compare_digest(payload.username.encode("utf-8"), auth.username.encode("utf-8"))
    if not (password_matches and username_matches):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    auth.invalidate(request.cookies.get(SESSION_COOKIE))
    token, session = auth.create_session()
    auth.set_cookie(response, token)
    return {
        "authenticated": True,
        "username": session.username,
        "csrf_token": session.csrf_token,
        "expires_in": auth.ttl,
    }


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response) -> Response:
    response.headers["Cache-Control"] = "no-store"
    if request.app.state.auth_mode == "demo":
        auth = _auth(request)
        if not auth.origin_allowed(request.headers.get("origin")):
            raise HTTPException(status_code=403, detail="Request origin is not allowed.")
        token = request.cookies.get(SESSION_COOKIE)
        session = auth.get_session(token)
        if session and not auth.csrf_valid(session, request.headers.get("x-csrf-token")):
            raise HTTPException(status_code=403, detail="CSRF validation failed.")
        auth.invalidate(token)
        auth.clear_cookie(response)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
