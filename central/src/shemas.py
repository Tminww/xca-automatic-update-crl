from pydantic import BaseModel


class RegistrationData(BaseModel):
    ip: str
    user: str
    signature: str
    cert_pem: str
