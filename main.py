#!/usr/bin/env python3
"""
main.py — простий вебдодаток + UDP Socket-сервер без фреймворків.

HTTP:
  - слухає на 0.0.0.0:3000
  - видає / (index.html), /message.html, /style.css, /logo.png
  - POST /message приймає форму (username, message), відправляє її UDP-пакетом
    на 127.0.0.1:5000 у форматі JSON і відповідає 302 Redirect на /

UDP Socket-сервер:
  - слухає на 0.0.0.0:5000
  - кожен отриманий JSON -> доповнює полем date=datetime.now()
  - зберігає документ у MongoDB (db: messages_db, coll: messages)
"""

from __future__ import annotations

import json
import socket
import urllib.parse
from datetime import datetime
from multiprocessing import Process
from pathlib import Path
from typing import Dict, Tuple

from pymongo import MongoClient

# ----------- Налаштування -----------

BASE_DIR = Path(__file__).parent.resolve()
STATIC_ROOT = BASE_DIR / "front-init"

# Виписуємо основні відомі маршрути:
STATIC = {
    "/": STATIC_ROOT / "index.html",
    "/index.html": STATIC_ROOT / "index.html",
    "/message.html": STATIC_ROOT / "message.html",
    "/style.css": STATIC_ROOT / "style.css",
    "/logo.png": STATIC_ROOT / "logo.png",
    "/error.html": STATIC_ROOT / "error.html",
}

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 3000

UDP_HOST = "0.0.0.0"
UDP_PORT = 5000

# Mongo — у docker-compose під’єднуємось за ім’ям сервісу "mongo"
MONGODB_URI = "mongodb://mongo:27017"
DB_NAME = "messages_db"
COLLECTION_NAME = "messages"


# ----------- Допоміжне -----------

def content_type(path: Path) -> str:
    suf = path.suffix.lower()
    if suf == ".html":
        return "text/html; charset=utf-8"
    if suf == ".css":
        return "text/css; charset=utf-8"
    if suf == ".png":
        return "image/png"
    return "application/octet-stream"


def http_response(status: str, headers: Dict[str, str], body: bytes) -> bytes:
    head = [f"HTTP/1.1 {status}"]
    for k, v in headers.items():
        head.append(f"{k}: {v}")
    head.append("")  # порожній рядок між заголовками і тілом
    start = ("\r\n".join(head) + "\r\n").encode("utf-8")
    return start + body


def read_http_request(conn: socket.socket) -> Tuple[str, str, Dict[str, str], bytes]:
    """Повертає (method, path, headers, body)."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            break
        data += chunk

    head, _, rest = data.partition(b"\r\n\r\n")
    head_text = head.decode("utf-8", "ignore")

    lines = head_text.split("\r\n")
    if not lines:
        return "", "", {}, b""

    request_line = lines[0]
    parts = request_line.split()
    if len(parts) < 2:
        return "", "", {}, b""
    method, path = parts[0], parts[1]

    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip().lower()] = v.strip()

    body = rest
    if method.upper() == "POST":
        try:
            clen = int(headers.get("content-length", "0"))
        except ValueError:
            clen = 0
        while len(body) < clen:
            chunk = conn.recv(4096)
            if not chunk:
                break
            body += chunk

    return method.upper(), path, headers, body


# ----------- HTTP-сервер -----------

def handle_get(path: str) -> bytes:
    # 1) спочатку шукаємо в явних маршрутах
    file_path = STATIC.get(path)

    # 2) якщо не знайшли — пробуємо віддати як статичний файл з STATIC_ROOT
    if not file_path:
        candidate = STATIC_ROOT / path.lstrip("/")
        if candidate.is_file():
            file_path = candidate

    if not file_path or not file_path.exists():
        fp = STATIC.get("/error.html")
        body = fp.read_bytes() if fp and fp.exists() else b"404 Not Found"
        return http_response(
            "404 Not Found",
            {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body))},
            body,
        )

    body = file_path.read_bytes()
    return http_response(
        "200 OK",
        {"Content-Type": content_type(file_path), "Content-Length": str(len(body))},
        body,
    )


def handle_post(path: str, headers: Dict[str, str], body: bytes) -> bytes:
    if path != "/message":
        fp = STATIC.get("/error.html")
        body_404 = fp.read_bytes() if fp and fp.exists() else b"404 Not Found"
        return http_response(
            "404 Not Found",
            {"Content-Type": "text/html; charset=utf-8", "Content-Length": str(len(body_404))},
            body_404,
        )

    # Парсимо форму application/x-www-form-urlencoded
    ctype = headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in ctype:
        form = urllib.parse.parse_qs(body.decode("utf-8", "ignore"))
        username = (form.get("username", [""])[0]).strip()
        message = (form.get("message", [""])[0]).strip()
    else:
        username, message = "", ""

    payload = {"username": username, "message": message}

    # Відправляємо UDP-повідомлення локальному сокет-серверу
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.sendto(json.dumps(payload).encode("utf-8"), ("127.0.0.1", UDP_PORT))
    except Exception as e:  # noqa: BLE001
        print(f"[HTTP] UDP send error: {e}")

    # Redirect на головну
    return http_response("302 Found", {"Location": "/"}, b"")


def http_server() -> None:
    print(f"[HTTP] Listening on http://0.0.0.0:{HTTP_PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HTTP_HOST, HTTP_PORT))
        srv.listen(128)
        while True:
            conn, addr = srv.accept()
            with conn:
                try:
                    method, path, headers, body = read_http_request(conn)
                    if method == "GET":
                        resp = handle_get(path)
                    elif method == "POST":
                        resp = handle_post(path, headers, body)
                    else:
                        resp = http_response("405 Method Not Allowed", {"Content-Length": "0"}, b"")
                    conn.sendall(resp)
                except Exception as e:  # noqa: BLE001
                    print(f"[HTTP] Error: {e}")
                    msg = b"Internal Server Error"
                    conn.sendall(
                        http_response(
                            "500 Internal Server Error",
                            {"Content-Type": "text/plain; charset=utf-8", "Content-Length": str(len(msg))},
                            msg,
                        )
                    )


# ----------- UDP Socket-сервер -----------

def udp_socket_server() -> None:
    print(f"[UDP] Listening on {UDP_HOST}:{UDP_PORT}, storing to MongoDB …")
    client = MongoClient(MONGODB_URI)
    coll = client[DB_NAME][COLLECTION_NAME]

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((UDP_HOST, UDP_PORT))
        while True:
            data, addr = sock.recvfrom(65535)
            try:
                payload = json.loads(data.decode("utf-8"))
                doc = {
                    "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                    "username": str(payload.get("username", "")).strip(),
                    "message": str(payload.get("message", "")).strip(),
                }
                coll.insert_one(doc)
                print(f"[UDP] Saved from {addr}: {doc}")
            except Exception as e:  # noqa: BLE001
                print(f"[UDP] Error processing packet from {addr}: {e}")


# ----------- Точка входу -----------

def main() -> None:
    p = Process(target=udp_socket_server, daemon=True)
    p.start()
    try:
        http_server()
    except KeyboardInterrupt:
        print("\n[MAIN] Stopping …")
    finally:
        if p.is_alive():
            p.terminate()
            p.join()


if __name__ == "__main__":
    main()