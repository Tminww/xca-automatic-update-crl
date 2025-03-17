from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import threading
import socket
import time
import uvicorn

app = FastAPI()

# Загрузка сертификата и приватного ключа ЦУЦ
with open("central_cert.pem", "rb") as f:
    central_cert = x509.load_pem_x509_certificate(f.read())
with open("central_key.pem", "rb") as f:
    central_key = serialization.load_pem_private_key(f.read(), password=None)

# Список зарегистрированных ПУЦ
registered_hosts = []
lock = threading.Lock()

# Модель для данных регистрации
class RegistrationData(BaseModel):
    data: str  # Формат: "IP,username"
    signature: str
    cert_pem: str

# Проверка подписи
def verify_signature(data: bytes, signature: bytes, cert: x509.Certificate):
    public_key = cert.public_key()
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        return True
    except:
        return False

# Эндпоинт для регистрации ПУЦ
@app.post("/register")
async def register(data: RegistrationData):
    try:
        puc_cert = x509.load_pem_x509_certificate(data.cert_pem.encode())
        if verify_signature(data.data.encode(), data.signature.encode(), puc_cert):
            ip, user = data.data.split(",")
            with lock:
                registered_hosts.append({"ip": ip, "user": user, "cert": puc_cert, "status": "active", "last_confirmed": time.time()})
            return {"message": "Registration successful"}
        else:
            raise HTTPException(status_code=400, detail="Invalid signature")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Эндпоинт для получения CRL
@app.get("/crl")
async def get_crl():
    with open("crl.pem", "rb") as f:
        crl = f.read()
    signature = central_key.sign(
        crl,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    return {"crl": crl.decode(), "signature": signature.decode()}

# Эндпоинт для подтверждения получения CRL
@app.post("/confirm")
async def confirm_receipt(request: Request):
    client_ip = request.client.host
    with lock:
        for host in registered_hosts:
            if host["ip"] == client_ip:
                host["last_confirmed"] = time.time()
                host["status"] = "active"
                return {"message": "Confirmation received"}
    raise HTTPException(status_code=404, detail="Host not found")

# UDP-сервер для heartbeat
def heartbeat_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("0.0.0.0", 12346))
    print("ЦУЦ: Сервер heartbeat запущен на порту 12346")
    while True:
        data, addr = server.recvfrom(1024)
        with lock:
            for host in registered_hosts:
                if host["ip"] == addr[0]:
                    host["last_confirmed"] = time.time()
                    host["status"] = "active"
                    print(f"ЦУЦ: Heartbeat от {host['ip']}")

# Отправка heartbeat
def send_heartbeat():
    while True:
        with lock:
            for host in registered_hosts:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(b"heartbeat", (host["ip"], 12347))
                if time.time() - host["last_confirmed"] > 10:
                    host["status"] = "inactive"
        time.sleep(5)

# Отображение состояния
def display_status():
    while True:
        with lock:
            print("\nЦУЦ: Состояние ПУЦ:")
            for host in registered_hosts:
                print(f"IP: {host['ip']}, User: {host['user']}, Status: {host['status']}, Last Confirmed: {host['last_confirmed']}")
        time.sleep(5)

# Запуск потоков
threading.Thread(target=heartbeat_server, daemon=True).start()
threading.Thread(target=send_heartbeat, daemon=True).start()
threading.Thread(target=display_status, daemon=True).start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)