from typing import Callable

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


def token_middleware_factory(valid_token: str) -> Callable:
    async def token_middleware(request: Request, call_next):
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Bearer "):
            return JSONResponse(
                {"detail": "Missing or invalid Authorization header"},
                status_code=status.HTTP_401_UNAUTHORIZED,
            )
        token = auth.split(" ", 1)[1].strip()
        if token != valid_token:
            return JSONResponse({"detail": "Invalid token"}, status_code=status.HTTP_401_UNAUTHORIZED)
        return await call_next(request)

    return token_middleware


app = FastAPI()
# Demo only: hard-coded token
app.middleware("http")(token_middleware_factory("secret-token"))


@app.get("/private")
async def private():
    return {"message": "You have access"}
