# Guión White Box — CWE-502 Deserialización Insegura

**Para:** Arias Felipe (82412) — el que explica el código en la exposición.
**TPI:** Seguridad en el Desarrollo de Software, UTN FRC, 4K3.
**Rol en la demo:** vos explicás el código vulnerable y la cadena de gadgets
mientras Cantero Santiago (81658) corre el exploit en vivo. Este archivo es
autocontenido — se lo podés pasar directo a tu agente (Claude Code, Copilot,
lo que uses) para que te ayude a prepararlo o ejecutarlo, no necesita que lea
nada más del repo.

> Si tu agente va a *ejecutar* algo de este archivo: el lab corre 100% en
> Docker/localhost, no toca nada fuera de `127.0.0.1`. No usar estos
> payloads contra otro sistema que no sea `target-app` de este repo.

---

## 0. Contexto en una frase

Hay un endpoint (`/cart/restore`) que recibe un objeto Java serializado en
Base64 y lo reconstruye con `ObjectInputStream.readObject()` sin validar
nada. Como en el classpath hay una librería vieja y vulnerable
(`commons-collections:3.1`), un atacante puede mandar un objeto armado a
mano que, al reconstruirse, ejecuta un comando arbitrario en el servidor —
sin explotar ningún bug de memoria ni inyección clásica. Esto es **CWE-502**
/ **OWASP A08:2021**.

Tu parte: explicar **por qué** esto funciona leyendo el código, antes de que
se vea el RCE corriendo. La diferencia con el enfoque caja negra (que hace
Santiago en la otra mitad de la demo) es justamente esta: con el código
delante no se prueba a ciegas, se *sabe de antemano* qué gadget va a andar.

---

## 1. Levantar el lab (antes de arrancar a hablar)

```powershell
cd C:\Users\santi\OneDrive\Escritorio\Facultad\Seguridad\lab-deserializacion
docker-compose build target-app
docker-compose up -d target-app
curl http://127.0.0.1:8080/cart/health
# -> vulnlab up
```

Abrir `http://127.0.0.1:8080/` en el navegador — es la tienda demo
"TechStore" (catálogo cosmético + botones que disparan el tráfico real).

---

## 2. PASO 1 — Encontrar el sink (qué decir + qué mostrar)

**Comando para mostrar en vivo:**

```bash
grep -rn "readObject\|ObjectInputStream" target-app/src/main/java
```

Esto tira dos resultados: `/cart/restore` (el vulnerable) y
`/cart/restore-filtered` (el mitigado). Mostrar el primero:

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

**Lo que decís:**

> "Acá está el sink. `new ObjectInputStream()` plano, sin ningún filtro, sobre
> un dato que viene directo del body del request — `@RequestBody`, controlado
> 100% por el cliente. Más abajo hay un `obj instanceof Cart` que chequea el
> tipo, pero eso corre *después* de `readObject()` — para cuando se llega ahí,
> si el stream trae una cadena de gadgets, el código arbitrario ya se
> ejecutó. El chequeo de tipo no previene nada, solo decide qué le
> respondemos al cliente."

---

## 3. PASO 2 — Identificar la librería y el CVE

```bash
cat target-app/pom.xml | grep -A2 commons-collections
```

```xml
<groupId>commons-collections</groupId>
<artifactId>commons-collections</artifactId>
<version>3.1</version>
```

**Lo que decís:**

> "La versión es 3.1. Eso cae en el rango vulnerable 3.0 a 3.2.1 de
> **CVE-2015-7501**, CVSS 9.8 — el fix real está en 3.2.2, que convierte
> `InvokerTransformer.readObject()` en una excepción explícita. Lo importante:
> esto no es un bug en el código de la app. Es tener una dependencia vieja en
> el classpath. La app no hace nada 'raro' a propósito."

---

## 4. PASO 3 — Elegir el gadget correcto *sin probar nada* (el punto fuerte del white box)

**Lo que decís (esta es la idea central de tu parte, remarcarla):**

> "Con el código a mano no hace falta fuerza bruta. Se sabe de entrada que la
> librería es `commons-collections:3.1` — eso descarta directo
> `CommonsCollections2` y `CommonsCollections4`, que necesitan
> `commons-collections4`, no presente. Quedan candidatos
> `CommonsCollections1/3/5/6/7`.
>
> Después se mira el JDK del target —" *(mostrar `target-app/Dockerfile`,
> imagen `eclipse-temurin:8-jre`, versión 8u512)* "— y ahí se descarta
> `CommonsCollections1` sin probarlo: ese gadget entra vía
> `AnnotationInvocationHandler.readObject()`, que Oracle parchó desde
> **JDK 8u71**. En este JDK (8u512, muy posterior al parche) tira
> `IncompleteAnnotationException` y no llega a ejecutar nada.
>
> El que sí funciona es `CommonsCollections6`: entra vía
> `HashSet/HashMap.readObject()` → `TiedMapEntry.hashCode()` → `LazyMap` —
> ninguna de esas clases es la parcheada. Es la elección directa, confirmada
> en este lab. Un atacante de caja negra prueba los 5 chains viables uno por
> uno hasta que algo responda distinto; nosotros con el código fuente vamos
> directo a CC6 sin mandar un solo payload de prueba."

---

## 5. PASO 4 — Mecánica del gadget chain, línea por línea

Esta parte es la más técnica. Sirve apoyarse en
`lab-deserializacion/exploit/WhiteBoxGadget.java` — es el gadget armado **a
mano**, sin usar la CLI de ysoserial, clase por clase, con comentarios que
mapean 1 a 1 con esta explicación.

**Lo que decís, paso por paso:**

1. **Punto de entrada**: el objeto serializado raíz es un `java.util.HashSet`
   con una sola entrada, cuya clave es un
   `org.apache.commons.collections.keyvalue.TiedMapEntry`.

2. `HashSet.readObject()` (clase estándar del JDK, no de la app) reconstruye
   internamente llamando `HashMap.put(key, value)` — y `put()` necesita
   `key.hashCode()` para ubicar el bucket.

3. `TiedMapEntry.hashCode()` **no calcula nada propio**: delega en
   `getValue()`, que llama `map.get(getKey())` sobre un mapa interno — en
   este payload, un `org.apache.commons.collections.map.LazyMap`.

4. `LazyMap.get(key)`: si la clave no existe, en vez de devolver `null` como
   un mapa normal, **invoca un `Transformer`** guardado como "factory" y usa
   el resultado como valor. Esta es la funcionalidad *legítima* de `LazyMap`
   (crear valores bajo demanda) — el gadget abusa de eso.

5. Ese `Transformer` es un `ChainedTransformer`, que ejecuta una lista en
   cadena, cada uno con el output del anterior como input:
   - `ConstantTransformer` → devuelve siempre `Runtime.class` (ignora el
     input).
   - `InvokerTransformer("getMethod", ...)` → sobre `Runtime.class`, invoca
     reflexivamente `.getMethod("getRuntime", null)`.
   - `InvokerTransformer("invoke", ...)` → invoca ese método estático →
     devuelve la instancia `Runtime` real del proceso.
   - `InvokerTransformer("exec", ...)` → invoca `.exec(comando)` sobre esa
     instancia → **acá se ejecuta el comando**.

6. Todo esto corrió **dentro de `readObject()`**, antes de que
   `CartController.restore()` llegue a la línea `obj instanceof Cart`. El
   chequeo de tipo nunca llega a tiempo de prevenir nada.

**La frase que resume todo (decirla tal cual, es la idea más importante):**

> "`InvokerTransformer` es básicamente `Method.invoke()` convertido en un
> objeto serializable. Apache Commons Collections lo diseñó para poder usar
> reflexión dentro de pipelines de transformación — funcionalidad legítima,
> nada malicioso en su diseño. Pero eso significa que cualquiera que pueda
> construir un `LazyMap` + `ChainedTransformer` desde cero puede encadenar
> *cualquier* llamada reflexiva a *cualquier* método público, incluido
> `Runtime.exec()`. El problema no es una línea de código rota: es que la
> deserialización nativa de Java reconstruye grafos de objetos completos
> —incluidos sus efectos colaterales (`hashCode()`, `readObject()` de cada
> clase)— sin que el programa que deserializa tenga ninguna chance de decir
> 'esto no lo esperaba'."

---

## 6. PASO 5 — Correr el exploit armado a mano (sin ysoserial)

Acá entra el script ya armado. A diferencia del exploit de caja negra
(`exploit/exploit.sh`, que usa la CLI de ysoserial), esto construye el mismo
objeto `LazyMap`/`ChainedTransformer`/`TiedMapEntry` **a mano**, clase por
clase, en `exploit/WhiteBoxGadget.java` — es la prueba de que entendiste la
cadena, no solo que corriste una herramienta.

```powershell
cd C:\Users\santi\OneDrive\Escritorio\Facultad\Seguridad\lab-deserializacion\exploit
.\run-whitebox.ps1
```

El script, en orden:
1. Verifica que estén el JDK8 portable (`tools/jdk8u512-b09`) y
   `commons-collections-3.1.jar` (extraído del fat jar de `target-app`).
2. Compila `WhiteBoxGadget.java`.
3. Lo corre, generando el payload serializado (bytes crudos, sin pasar por
   redirección de texto de PowerShell que lo corrompería).
4. Lo manda en Base64 a `POST /cart/restore`.
5. Verifica dentro del container (`docker exec target-app cat
   /tmp/whitebox_output.txt`) que el comando corrió.

**Salida esperada:** `uid=0(root) gid=0(root) groups=0(root)`.

Al final el script imprime el comando `curl` equivalente — útil para
repetir el envío a mano o pegarlo en Burp Repeater sin correr PowerShell de
nuevo.

**Variantes útiles:**

```powershell
.\run-whitebox.ps1 -Command "whoami"          # otro comando
.\run-whitebox.ps1 -PrintOnly                 # solo genera y muestra el Base64, no envía nada
```

**Lo que decís mientras corre:**

> "Esto no usa ysoserial. Es el mismo gadget chain armado a mano, clase por
> clase, en `WhiteBoxGadget.java` — construyo el `ChainedTransformer`, lo meto
> en un `LazyMap`, lo cuelgo de un `TiedMapEntry`, y lo inyecto como clave real
> de un `HashSet` por reflexión, porque si llamara `hashCode()` yo mismo en
> este proceso, el comando se ejecutaría *acá*, no en el servidor. Después lo
> serializo con `ObjectOutputStream` normal, igual que haría la app si
> guardara un carrito real."

---

## 7. PASO 6 — Mostrar la mitigación (por qué se frena)

```java
// WhitelistObjectInputStream.java:45-52
@Override
protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
    String name = desc.getName();
    if (!ALLOWED_CLASSES.contains(name)) {
        throw new InvalidClassException(name, "Clase no permitida por whitelist de deserializacion");
    }
    return super.resolveClass(desc);
}
```

**Lo que decís:**

> "`resolveClass()` corre para **cada clase** que el stream necesita
> resolver, **antes** de instanciarla — antes del paso 1 de la cadena que
> expliqué. El whitelist solo permite `Cart`, `CartItem`, `ArrayList`,
> `String`. `HashSet`, `TiedMapEntry`, `LazyMap`, `ChainedTransformer`,
> `InvokerTransformer` no están — la excepción salta en la primera clase
> ajena, antes de que `LazyMap.get()` exista siquiera como objeto. No importa
> cuál de los 5 gadgets viables de esta librería se use: todos dependen de
> clases que no son `Cart`/`CartItem`, todos quedan afuera por el mismo
> mecanismo."

**Demo (correr contra el endpoint mitigado):**

```powershell
.\run-whitebox.ps1 -TargetUrl "http://127.0.0.1:8080/cart/restore-filtered"
```

> Nota: si el script tira error de verificación porque el endpoint mitigado
> devuelve otro formato de respuesta, no es un bug — mostrar igual la
> respuesta del server ("Rechazado por ObjectInputFilter: ...", ver nota de
> wording más abajo) y aclarar que el rechazo es lo esperado.

> **Aclaración de wording** (si alguien pregunta): el mensaje de rechazo del
> server dice "Rechazado por ObjectInputFilter", pero la implementación real
> **no es** `java.io.ObjectInputFilter` (JEP 290) — esa API **no existe en
> OpenJDK 8** (verificado directo con `javac`). Es el texto del mensaje,
> nomás; la implementación real es el override de `resolveClass()` de arriba,
> técnica clásica disponible desde Java 5.

---

## 8. Guión resumido (si hay que cortar tiempo, decir solo esto)

1. "El sink está en `CartController.java:97` — un `readObject()` sin ningún
   filtro, sobre datos que vienen del cliente."
2. "La librería es `commons-collections:3.1`, vulnerable por
   `CVE-2015-7501`, CVSS 9.8."
3. "El JDK es 8u512, parchado desde 8u71 — eso descarta `CommonsCollections1`
   de entrada, sin necesidad de probarlo."
4. "El gadget que funciona, `CommonsCollections6`, abusa de `LazyMap` +
   `InvokerTransformer` — reflexión encadenada que termina en
   `Runtime.exec()`, todo con clases de la librería, nada del código de la
   app."
5. "La mitigación real intercepta esto en `resolveClass()` — rechaza la
   clase antes de que exista como objeto, en
   `WhitelistObjectInputStream.java:48`."

---

## 9. Troubleshooting (si tu agente corre el script y rompe)

Tres trampas ya resueltas en este lab, para no perder tiempo re-descubriéndolas:

1. **`java`/`javac` del sistema es JDK 21** (module system) → tira
   `InaccessibleObjectException` al hacer `setAccessible()` sobre
   `HashSet`/`HashMap` internos. El script usa el JDK8 portable
   (`tools/jdk8u512-b09/bin/java.exe`) automáticamente — no cambiar eso.
2. **PowerShell corrompe binarios con `>`** — el redirect nativo re-encodea
   el stdout como texto y mete un BOM, el server tira
   `invalid stream header: FFFEBC00`. El script ya evita esto capturando
   bytes crudos vía `System.Diagnostics.Process`.
3. **PowerShell 5.1 + `2>&1` sobre un exe nativo** con
   `$ErrorActionPreference = "Stop"` activo convierte salida normal a stderr
   (como `java -version`) en un error terminante falso. El script también
   evita esto.

Si falta `commons-collections-3.1.jar` en `exploit/`, extraerlo del fat jar
de `target-app`:

```powershell
docker cp target-app:/app/vulnlab.jar vulnlab.jar
# Extraer BOOT-INF/lib/commons-collections-3.1.jar de ese zip hacia exploit/
```

---

## 10. Apagar todo al terminar

```powershell
docker-compose down
```
