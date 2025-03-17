from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
print(BASE_DIR)


class Config(BaseSettings):
    # Общие настройки
    ROOT_DIR: Path = BASE_DIR
    central_host: str = "127.0.0.1"  # IP-адрес центрального сервера (ЦУЦ)
    central_port: int = 8000  # Порт FastAPI-сервера ЦУЦ
    heartbeat_port_central: int = 12346  # UDP-порт для heartbeat на ЦУЦ
    heartbeat_port_subordinate: int = 12347  # UDP-порт для heartbeat на ПУЦ

    # Настройки для ЦУЦ
    central_cert_path: str = "central_cert.pem"  # Путь к сертификату ЦУЦ
    central_key_path: str = "central_key.pem"  # Путь к приватному ключу ЦУЦ
    crl_path: str = "crl.pem"  # Путь к CRL-файлу на ЦУЦ

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
