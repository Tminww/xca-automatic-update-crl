from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
print(ROOT_DIR)


class Config(BaseSettings):
    # Общие настройки
    root_dir: Path = ROOT_DIR
    root_host: str = "127.0.0.1"  # IP-адрес центрального сервера (ЦУЦ)
    root_port: int = 8000  # Порт FastAPI-сервера ЦУЦ

    # Настройки для ЦУЦ
    absolute_root_cert_path: str = "root_cert.pem"  # Путь к сертификату ЦУЦ
    absolute_root_key_path: str = "root_key.pem"  # Путь к приватному ключу ЦУЦ
    absolute_crl_path: str = "crl.pem"  # Путь к CRL-файлу на ЦУЦ

    # Опциональные настройки
    proxy: Optional[str] = (
        None  # Прокси для ПУЦ, если требуется (например, "http://proxy:port")
    )

    # Конфигурация для загрузки из файла .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",  # Игнорировать лишние переменные в .env
    )


# Создание экземпляра конфигурации
settings = Config()
