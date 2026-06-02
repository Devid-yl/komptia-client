"""Services d'authentification.

* ``password_hasher``    — bcrypt, verify, needs_rehash
* ``session_manager``    — cycle de vie des sessions BDD
* ``login_rate_limiter`` — bruteforce per-IP + per-account (ASVS V2.2.1)
"""

from app.services.auth.login_rate_limiter import (
    LoginRateLimiter,
    get_login_rate_limiter,
    reset_login_rate_limiter,
)
from app.services.auth.password_hasher import PasswordHasher
from app.services.auth.session_manager import (
    SessionManager,
    get_session_manager,
    reset_session_manager,
)

__all__ = [
    "LoginRateLimiter",
    "PasswordHasher",
    "SessionManager",
    "get_login_rate_limiter",
    "get_session_manager",
    "reset_login_rate_limiter",
    "reset_session_manager",
]
