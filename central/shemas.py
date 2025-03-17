import ipaddress
from pydantic import BaseModel, validator


class RegistrationData(BaseModel):
    ip: str
    port: int
    user: str
    signature: str
    cert_pem: str

    @validator("ip")
    def validate_ip(v):
        try:
            # Проверка, что строка является валидным IP-адресом
            ip = ipaddress.ip_address(v)
            return str(ip)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {e}")
