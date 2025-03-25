import requests
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from cryptography import x509
from cryptography.x509 import load_der_x509_crl
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import CRLEntryExtensionOID
import logging
import asyncio
from datetime import datetime
from contextlib import asynccontextmanager
from config import settings

UPDATE_RATE_IN_SEC = 30 

@asynccontextmanager
async def lifespan(app: FastAPI):
    asyncio.create_task(update_crl())
    await register()
    yield
    logger.info("ПУЦ завершил работу")

app = FastAPI(lifespan=lifespan)

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(f"{settings.root_dir}/logs/under_server.log"),
        logging.StreamHandler(),
    ],
)
logger = logging.getLogger(__name__)

# Глобальные переменные
last_update_time = None
revoked_certs_list = []
server_status = "Disconnected"

# Загрузка сертификата и приватного ключа ПУЦ
with open(settings.absolute_puc_cert_path, "rb") as f:
    puc_cert = x509.load_pem_x509_certificate(f.read())
with open(settings.absolute_puc_key_path, "rb") as f:
    puc_key = serialization.load_pem_private_key(f.read(), password=None)


# Чтение HTML из файла
with open(f"{settings.root_dir}/templates/index.html", "r", encoding="utf-8") as f:
    html = f.read()
    
# Подпись данных
def sign_data(ip, user):
    data = f"{ip},{user}".encode()
    signature = puc_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

def verify_crl(root_cert_pem, crl_bytes):
    try:
        root_cert = x509.load_pem_x509_certificate(root_cert_pem)
        crl = load_der_x509_crl(crl_bytes)
        public_key = root_cert.public_key()
        public_key.verify(
            signature=crl.signature,
            data=crl.tbs_certlist_bytes,
            padding=padding.PKCS1v15(),
            algorithm=crl.signature_hash_algorithm
        )
        logger.info("CRL signature verification successful")
        return crl
    except Exception as e:
        logger.error(f"CRL verification failed: {str(e)}")
        return None

async def register():
    ip = settings.puc_host
    user = settings.puc_user
    signature = sign_data(ip, user)
    cert_pem = puc_cert.public_bytes(serialization.Encoding.PEM).decode()
    
    payload = {
        "ip": ip,
        "user": user,
        "port": settings.puc_port,
        "signature": signature.hex(),
        "cert_pem": cert_pem
    }
    
    try:
        response = requests.post(
            f"http://{settings.root_host}:{settings.root_port}/register",
            json=payload
        )
        if response.status_code == 200:
            logger.info(f"ЦУЦ: Ответ: {response.json()}")
        else:
            logger.error(f"ЦУЦ: Ошибка при регистрации: {response.json().get('detail', 'Unknown error')}")
    except requests.exceptions.RequestException as e:
        logger.error(f"ПУЦ: Ошибка при регистрации: {e}")

async def update_crl():
    global last_update_time, revoked_certs_list, server_status
    while True:
        try:
            response = requests.get(f"http://{settings.root_host}:{settings.root_port}/crl")
            response.raise_for_status()
            data = response.json()
            
            crl_bytes = bytes.fromhex(data.get("crl"))
            root_cert_pem = data.get("root_cert").encode()

            crl = verify_crl(root_cert_pem, crl_bytes)
            if crl is None:
                server_status = "Disconnected"
                logger.error("CRL verification failed, skipping")
                continue

            server_status = "Connected"
            revoked_certs_list = list(crl)
            last_update_time = datetime.now()

            with open("mock/CRL.pem", "wb") as f:
                f.write(crl.public_bytes(serialization.Encoding.PEM))
            logger.info("CRL успешно обновлён")
                
        except Exception as e:
            server_status = "Disconnected"
            logger.error(f"Ошибка: {str(e)}")
        await asyncio.sleep(delay=UPDATE_RATE_IN_SEC)

# Функция для получения причины отзыва
def get_revocation_reason(cert):
    try:
        logger.debug(f"Checking extensions for cert with serial: {cert.serial_number:x}")
        ext = cert.extensions.get_extension_for_oid(CRLEntryExtensionOID.CRL_REASON)
        reason = ext.value  # Это объект CRLReason
        logger.debug(f"Found CRLReason: {reason}")
        
        # Извлекаем строковое представление причины
        reason_name = reason.reason.name if reason.reason else "unspecified"
        logger.debug(f"Extracted reason name: {reason_name}")
        return reason_name
    except x509.ExtensionNotFound:
        logger.debug("CRLReason extension not found")
        return "unspecified"
    except Exception as e:
        logger.error(f"Error getting revocation reason: {str(e)}")
        return "Ошибка при получении причины"



@app.get("/", response_class=HTMLResponse)
async def root():
    return html

@app.get("/status")
async def get_status():
    return {
        "server_status": server_status,
        "last_update": last_update_time.isoformat() if last_update_time else None,
        "revoked_certs": [
            {
                "serial_number": f"{cert.serial_number:x}",
                "revocation_reason": get_revocation_reason(cert),
                "revocation_date": cert.revocation_date_utc.isoformat() if cert.revocation_date_utc else None
            } for cert in revoked_certs_list
        ],
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.puc_host, port=settings.puc_port)