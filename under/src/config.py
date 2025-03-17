from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
print(BASE_DIR)


class Config(BaseSettings):
    # Общие настройки
    central_host: str = "127.0.0.1"  # IP-адрес центрального сервера (ЦУЦ)
    central_port: int = 8000  # Порт FastAPI-сервера ЦУЦ
    heartbeat_port_central: int = 12346  # UDP-порт для heartbeat на ЦУЦ
    heartbeat_port_subordinate: int = 12347  # UDP-порт для heartbeat на ПУЦ

    # Настройки для ПУЦ
    subordinate_ip: str = "192.168.1.10"  # IP-адрес подчинённого компьютера
    subordinate_user: str = "user1"  # Имя пользователя ПУЦ
    puc_cert_path: str = "puc_cert.pem"  # Путь к сертификату ПУЦ
    puc_key_path: str = "puc_key.pem"  # Путь к приватному ключу ПУЦ
    local_crl_path: str = "local_crl.pem"  # Путь для сохранения CRL на ПУЦ

    # Опциональные настройки
    proxy: Optional[str] = (
        None  # Прокси для ПУЦ, если требуется (например, "http://proxy:port")
    )

    # Настройки интервалов
    heartbeat_interval: int = 5  # Интервал отправки heartbeat (секунды)
    crl_check_interval: int = 1800  # Интервал проверки CRL на ПУЦ (секунды)

    # Конфигурация для загрузки из файла .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Игнорировать лишние переменные в .env
    )


# Создание экземпляра конфигурации
settings = Config()
