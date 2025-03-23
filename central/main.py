import json
import os
import aiofiles
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import CRLEntryExtensionOID
import logging
import aiohttp
import asyncio
from datetime import datetime
from shemas import RegistrationData
from config import settings

HOSTS_FILE = f"{settings.root_dir}/hosts.json"

app = FastAPI()

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

# Настройка CORS
origins = ["http://localhost:5173"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Загрузка приватного ключа и сертификата ЦУЦ
with open(settings.absolute_root_key_path, "rb") as f:
    root_key = serialization.load_pem_private_key(f.read(), password=None)
with open(settings.absolute_root_cert_path, "rb") as f:
    root_cert_pem = f.read()
    root_cert = x509.load_pem_x509_certificate(root_cert_pem)


# Чтение HTML из файла
with open(f"{settings.root_dir}/templates/index.html", "r", encoding="utf-8") as f:
    html = f.read()
# Глобальная переменная для хранения CRL
crl = None

def verify_signature(data, signature, cert):
    public_key = cert.public_key()
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

async def write_hosts(hosts):
    try:
        os.makedirs(os.path.dirname(HOSTS_FILE), exist_ok=True)
        async with aiofiles.open(HOSTS_FILE, "w", encoding="utf-8") as f:
            await f.write(json.dumps(hosts, indent=2, ensure_ascii=False))
        logger.info(f"Hosts written to {HOSTS_FILE}")
    except Exception as e:
        logger.error(f"Failed to write hosts: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка записи хостов: {e}")

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

@app.post("/register")
async def register(data: RegistrationData):
    try:
        puc_cert = x509.load_pem_x509_certificate(data.cert_pem.encode())
        reg_data = f"{data.ip},{data.user}".encode()
        if not verify_signature(reg_data, bytes.fromhex(data.signature), puc_cert):
            logger.warning(f"Invalid signature for registration attempt from IP: {data.ip}")
            raise HTTPException(status_code=400, detail="Invalid signature")

        new_host = {
            "ip": data.ip,
            "port": data.port,
            "user": data.user,
            "status": "Disconnected",
            "last_confirmed": datetime.utcnow().isoformat() + "Z"
        }

        registered_hosts = await read_hosts()
        
        # Проверка уникальности IP
        for host in registered_hosts:
            if host["ip"] == data.ip:
                logger.warning(f"Registration failed: IP {data.ip} already registered")
                raise HTTPException(status_code=409, detail=f"IP address {data.ip} already registered")

        registered_hosts.append(new_host)
        await write_hosts(registered_hosts)
        logger.info(f"Зарегистрирован ПУЦ: IP: {data.ip}, User: {data.user}")
        return {"message": "Registration successful"}
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Registration failed: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    
@app.get("/crl")
async def get_crl():
    global crl
    try:
        with open(settings.absolute_crl_path, "rb") as f:
            crl_pem = f.read()
            try:
                crl = x509.load_pem_x509_crl(crl_pem)
            except ValueError:
                logger.error("Файл %s не является CRL!", settings.absolute_crl_path)
                raise HTTPException(status_code=500, detail="Invalid CRL file")
            crl_der = crl.public_bytes(serialization.Encoding.DER)
            return {
                "crl": crl_der.hex(),
                "root_cert": root_cert_pem.decode()
            }
    except Exception as e:
        logger.error(f"Ошибка: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_status():
    global crl
    if crl is None:
        try:
            with open(settings.absolute_crl_path, "rb") as f:
                crl_pem = f.read()
                crl = x509.load_pem_x509_crl(crl_pem)
        except Exception as e:
            logger.error(f"Failed to load CRL: {str(e)}")
            return {
                "revoked_certs": []
            }

    return {
        "revoked_certs": [
            {
                "serial_number": f"{cert.serial_number:x}",
                "revocation_reason": get_revocation_reason(cert),
                "revocation_date": cert.revocation_date_utc.isoformat() if cert.revocation_date_utc else None
            } for cert in crl
        ]
    }

async def check_host_status(host):
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://{host['ip']}:{host['port']}/status"
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=2)) as response:
                if response.status == 200:
                    host["status"] = "Connected"
                    host["last_confirmed"] = datetime.utcnow().isoformat() + "Z"
                else:
                    host["status"] = "Disconnected"
    except Exception:
        host["status"] = "Disconnected"

async def update_host_statuses():
    while True:
        hosts = await read_hosts()
        tasks = [check_host_status(host) for host in hosts]
        await asyncio.gather(*tasks)
        await write_hosts(hosts)
        await asyncio.sleep(settings.update_rate)


@app.get("/", response_class=HTMLResponse)
async def root():
    return html

@app.get("/hosts")
async def get_hosts():
    return await read_hosts()

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(update_host_statuses())

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=settings.root_host, port=settings.root_port)