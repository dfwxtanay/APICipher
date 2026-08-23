from pydantic import BaseModel


class UserCreate(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str

class TransactionCreate(BaseModel):
    amount: float
    description: str

class UserPublic(BaseModel):
    """Explicit allowlist of user fields safe to return.

    VULN (APC-005, APC-011): returning ORM objects directly serialises every
    column, so the password hash leaks. Listing fields explicitly means a new
    sensitive column cannot leak by default.
    """

    id: int
    username: str
    email: str
    role: str

    model_config = {"from_attributes": True}
