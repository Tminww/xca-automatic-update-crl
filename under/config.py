from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional
from pathlib import Path

# Определение корневой директории
ROOT_DIR = Path(__file__).resolve().parent

# Класс конфигурации
class Config(BaseSettings):
    root_dir: Path = ROOT_DIR

    puc_port: int = 8001
    puc_host: str = "127.0.0.1"
    puc_user: str = "user"
    
    root_port: int = 8000
    root_host: str = "127.0.0.1"

    absolute_puc_cert_path: str = "puc_cert.pem"  # Путь к сертификату ПУЦ
    absolute_puc_key_path: str = "puc_key.pem"    # Путь к приватному ключу ПУЦ
    absolute_crl_path: str = "local_crl.pem"      # Путь для сохранения CRL на ПУЦ

    # Опциональные настройки
    proxy: Optional[str] = None

    # Конфигурация для загрузки из файла .env
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

# Создание экземпляра конфигурации
settings = Config()
