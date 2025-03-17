import json
import os
import aiofiles
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging
from datetime import datetime
import uvicorn
from config import settings
from shemas import RegistrationData

HOSTS_FILE = f"{settings.ROOT_DIR}/hosts.json"

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(
            f"{settings.ROOT_DIR}/logs/central_server.log"
        ),  # Логи в файл
        logging.StreamHandler(),  # Логи в консоль
    ],
)
logger = logging.getLogger(__name__)

app = FastAPI()


# Настройка CORS
origins = ["http://localhost:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# # Загрузка сертификата и приватного ключа ЦУЦ
# with open(f"{settings.central_cert_path}", "rb") as f:
#     central_cert = x509.load_pem_x509_certificate(f.read())
# with open(f"{settings.central_key_path}", "rb") as f:
#     central_key = serialization.load_pem_private_key(f.read(), password=None)

# Список зарегистрированных ПУЦ
registered_hosts = []


# Функция для чтения текущей истории (асинхронная)
async def read_hosts():
    if os.path.exists(HOSTS_FILE):
        async with aiofiles.open(HOSTS_FILE, "r", encoding="utf-8") as f:
            content = await f.read()
            if not content.strip():  # Проверяем, пуст ли файл
                print("History file is empty")
                return []
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                print(f"Failed to parse history: {e}")
                return []
    return []


# Функция для записи истории (асинхронная)
async def write_hosts(history):
    try:
        os.makedirs(
            os.path.dirname(HOSTS_FILE), exist_ok=True
        )  # Создаём директорию, если её нет
        async with aiofiles.open(HOSTS_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(history, indent=2, ensure_ascii=False))
        print(f"History written to {HOSTS_FILE}")
    except Exception as e:
        print(f"Failed to write history: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка записи истории: {str(e)}")


# Эндпоинт для регистрации ПУЦ
@app.post("/register")
async def register(data: RegistrationData):
    try:
        new_host = {
            "ip": data.ip,
            "user": data.user,
            "status": "active",
            "last_confirmed": datetime.utcnow().isoformat() + "Z",
        }

        registered_hosts = await read_hosts()
        registered_hosts.append(new_host)
        await write_hosts(registered_hosts)
        logger.info(f"Зарегистрирован ПУЦ: IP: {data.ip}, User: {data.user}")
        return {"message": "Registration successful"}

    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# # Эндпоинт для получения CRL
# @app.get("/crl")
# async def get_crl():
#     with open("crl.pem", "rb") as f:
#         crl = f.read()
#     signature = central_key.sign(
#         crl,
#         padding.PSS(
#             mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
#         ),
#         hashes.SHA256(),
#     )
#     return {"crl": crl.decode(), "signature": signature.decode()}


# # Эндпоинт для подтверждения получения CRL
# @app.post("/confirm")
# async def confirm_receipt(request: Request):
#     client_ip = request.client.host
#     with lock:
#         for host in registered_hosts:
#             if host["ip"] == client_ip:
#                 host["last_confirmed"] = time.time()
#                 host["status"] = "active"
#                 return {"message": "Confirmation received"}
#     raise HTTPException(status_code=404, detail="Host not found")


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
