import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import logging
import time
from config import settings

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

# Загрузка сертификата и приватного ключа ПУЦ
with open(settings.absolute_puc_cert_path, "rb") as f:
    puc_cert = x509.load_pem_x509_certificate(f.read())
with open(settings.absolute_puc_key_path, "rb") as f:
    puc_key = serialization.load_pem_private_key(f.read(), password=None)

# Подпись данных
def sign_data(ip, user):
    data = f"{ip},{user}".encode()
    signature = puc_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return signature

# Проверка подписи CRL с использованием сертификата ПУЦ
def verify_crl(crl, signature, root_cert):
    public_key = root_cert.public_key()
    try:
        public_key.verify(
            signature,
            crl,
            padding.PKCS1v15(),  # Если CRL подписан без PSS
            hashes.SHA256()
        )
        return True
    except Exception as e:
        logger.error(f"CRL signature verification failed: {e}")
        return False
# Регистрация на ЦУЦ
def register():
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
        if e.response is not None:
            logger.error(f"ПУЦ: Детали ошибки: {e.response.text}")

# Получение и обновление CRL
def update_crl():
    with open(settings.absolute_puc_cert_path, "rb") as f:
        root_cert = x509.load_pem_x509_certificate(f.read())
    
    while True:
        try:
            response = requests.get(f"http://{settings.root_host}:{settings.root_port}/crl")
            response.raise_for_status()
            data = response.json()
            crl = bytes.fromhex(data["crl"])
            signature = bytes.fromhex(data["signature"])
            
            if verify_crl(crl, signature, root_cert):
                with open(settings.absolute_crl_path, "wb") as f:
                    f.write(crl)
                logger.info(f"CRL updated and saved to {settings.absolute_crl_path}")
            else:
                logger.warning("Invalid CRL signature")
        except requests.exceptions.RequestException as e:
            logger.error(f"Ошибка получения CRL: {e}")
            if e.response is not None:
                logger.error(f"Детали ошибки: {e.response.text}")
        time.sleep(1800)
# Запуск
if __name__ == "__main__":
    logger.info("Начало работы ПУЦ")
    register()
    update_crl()