import json
import os
import aiofiles
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging
from datetime import datetime
import uvicorn
from shemas import RegistrationData
from config import settings

HOSTS_FILE = f"{settings.root_dir}/hosts.json"

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{settings.root_dir}/logs/root_server.log"),
        logging.StreamHandler(),
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

# Загрузка приватного ключа ЦУЦ для подписи CRL
with open(settings.absolute_root_key_path, "rb") as f:
    root_key = serialization.load_pem_private_key(f.read(), password=None)
    
# Функция для проверки подписи
def verify_signature(data, signature, cert):
    public_key = cert.public_key()
    print(public_key)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"Signature verification failed: {e}")
        return False

# Асинхронное чтение хостов
async def read_hosts():
    if os.path.exists(HOSTS_FILE):
        async with aiofiles.open(HOSTS_FILE, "r", encoding="utf-8") as f:
            content = await f.read()
            if not content.strip():
                logger.info("Hosts file is empty")
                return []
            try:
                return json.loads(content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse hosts: {e}")
                return []
    return []

# Асинхронная запись хостов
async def write_hosts(hosts):
    try:
        os.makedirs(os.path.dirname(HOSTS_FILE), exist_ok=True)
        async with aiofiles.open(HOSTS_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(hosts, indent=2, ensure_ascii=False))
        logger.info(f"Hosts written to {HOSTS_FILE}")
    except Exception as e:
        logger.error(f"Failed to write hosts: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка записи хостов: {e}")

# Эндпоинт для регистрации ПУЦ
@app.post("/register")
async def register(data: RegistrationData):
    try:
        # Загружаем сертификат ПУЦ из переданных данных
        puc_cert = x509.load_pem_x509_certificate(data.cert_pem.encode())
        print(puc_cert)
        # Данные для подписи: IP и имя пользователя
        reg_data = f"{data.ip},{data.user}".encode()
        print(reg_data)
        # Проверка подписи
        if not verify_signature(reg_data, bytes.fromhex(data.signature), puc_cert):
            logger.warning(f"Invalid signature for registration attempt from IP: {data.ip}")
            raise HTTPException(status_code=400, detail="Invalid signature")

        new_host = {
            "ip": data.ip,
            "port": data.port,
            "user": data.user,
            "status": "active",
            "last_confirmed": datetime.utcnow().isoformat() + "Z"
        }

        registered_hosts = await read_hosts()
        # Проверка уникальности IP
        # for host in registered_hosts:
        #     if host["ip"] == data.ip:
        #         logger.warning(f"Registration failed: IP {data.ip} already exists")
        #         raise HTTPException(status_code=409, detail="IP address already registered")

        registered_hosts.append(new_host)
        await write_hosts(registered_hosts)
        logger.info(f"Зарегистрирован ПУЦ: IP: {data.ip}, User: {data.user}")
        return {"message": "Registration successful"}

    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))

# Эндпоинт для получения CRL
@app.get("/crl")
async def get_crl():
    try:
        with open(settings.absolute_crl_path, "rb") as f:
            crl = f.read()
        signature = root_key.sign(
            crl,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        logger.info("CRL requested and sent")
        return {"crl": crl.hex(), "signature": signature.hex()}
    except Exception as e:
        logger.error(f"Failed to serve CRL: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка получения CRL: {e}")
    
if __name__ == "__main__":
    logger.info(f"Запущен ЦУЦ на {settings.root_host}:{settings.root_port}")
    uvicorn.run(app, host=settings.root_host, port=settings.root_port)