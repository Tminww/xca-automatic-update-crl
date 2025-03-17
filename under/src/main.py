import requests
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import socket
import threading
import time

# Загрузка сертификата и ключа ПУЦ
with open("puc_cert.pem", "rb") as f:
    puc_cert = x509.load_pem_x509_certificate(f.read())
with open("puc_key.pem", "rb") as f:
    puc_key = serialization.load_pem_private_key(f.read(), password=None)

# Загрузка сертификата ЦУЦ для проверки CRL
with open("central_cert.pem", "rb") as f:
    central_cert = x509.load_pem_x509_certificate(f.read())

# Данные ПУЦ
ip = "192.168.1.10"  # Замените на ваш IP
user = "user1"
data = f"{ip},{user}"
signature = puc_key.sign(
    data.encode(),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256()
)
cert_pem = puc_cert.public_bytes(serialization.Encoding.PEM).decode()

# Регистрация на ЦУЦ
def register():
    response = requests.post("http://127.0.0.1:8000/register", json={
        "data": data,
        "signature": signature.decode(),
        "cert_pem": cert_pem
    })
    print(f"ПУЦ: Ответ от ЦУЦ: {response.json()}")

# Получение и проверка CRL
def get_crl():
    response = requests.get("http://127.0.0.1:8000/crl")
    crl = response.json()["crl"].encode()
    signature = response.json()["signature"].encode()
    public_key = central_cert.public_key()
    try:
        public_key.verify(
            signature,
            crl,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        with open("local_crl.pem", "wb") as f:
            f.write(crl)
        print(f"ПУЦ: CRL получен и сохранён, время: {time.time()}")
        requests.post("http://127.0.0.1:8000/confirm")
    except:
        print("ПУЦ: Ошибка проверки подписи CRL")

# UDP-сервер для heartbeat
def heartbeat_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 12347))
    print("ПУЦ: Сервер heartbeat запущен на порту 12347")
    while True:
        data, addr = server.recvfrom(1024)
        if data == b"heartbeat":
            server.sendto(b"alive", addr)
            print("ПУЦ: Отправлен heartbeat-ответ")

# Запуск
register()
threading.Thread(target=heartbeat_server, daemon=True).start()

# Периодическое получение CRL (каждые 30 минут)
while True:
    get_crl()
    time.sleep(1800)