# Tienda Demo (CWE-502) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reemplazar el dashboard de botones actual (`static/index.html`) por una tienda narrativa (catálogo + carrito + "ver carrito guardado") que dispara el POST real a `/cart/restore` / `/cart/restore-filtered`, para que Burp Suite intercepte tráfico de compra genuino en la demo; y agregar un modo `PRINT_ONLY` a `exploit.sh` para generar el payload Base64 sin enviarlo, pegable a mano en Burp Repeater.

**Architecture:** Front estático de un solo archivo (sigue el patrón ya usado), JS vanilla sin build step, cero cambios de backend. `exploit.sh` gana una rama condicional controlada por variable de entorno que corta antes del `curl -X POST`.

**Tech Stack:** HTML/CSS/JS vanilla (sin frameworks, consistente con el archivo actual), bash (exploit.sh), Spring Boot backend sin tocar.

**Spec:** Diseño acordado en conversación (brainstorming skill) — ver resumen abajo, no hay archivo de spec separado (cambio chico).

## Global Constraints

- Backend (`CartController.java`, endpoints `/cart/health`, `/cart/save`, `/cart/restore`, `/cart/restore-filtered`, `/cart/debug-output`) NO se modifica — ya verificado en Docker real.
- `static/` se hornea dentro del jar en build time — todo cambio de front requiere `docker-compose build target-app && docker-compose up -d target-app` antes de verificar.
- En Git Bash/Windows, cualquier arg que empiece con `/` (ej. `/cart/restore-filtered`) necesita `MSYS_NO_PATHCONV=1` adelante del comando o se traduce a ruta Windows.
- Catálogo: 3 productos — Notebook $850.000, Mouse $12.000, Teclado $35.000 (Notebook/Mouse coinciden con el carrito fijo que devuelve `/cart/save`; Teclado es solo decorativo del catálogo).
- "Agregar al carrito" es 100% cosmético (estado JS local) — no dispara red. La vulnerabilidad real se dispara solo con los botones de "ver carrito guardado".

## Review Focus

- **Botón mitigado apuntando al endpoint equivocado:** dos botones casi idénticos ("ver carrito guardado" / "ver carrito guardado (seguro)") — si el segundo llama a `/cart/restore` en vez de `/cart/restore-filtered`, la demo de mitigación miente. Test: verificar que cada botón arma la URL correcta antes de togglear.
- **Reintroducir el bug de `classList.add('')`:** ya se arregló una vez en el dashboard viejo (ver historial); el rewrite tiene que usar el patrón condicional, no la forma vieja.
- **`PRINT_ONLY` enviando igual el payload:** si la rama condicional queda mal ubicada (después del `curl -X POST` en vez de antes), el modo "solo imprimir" termina ejecutando RCE igual, lo cual es peligroso explicar mal en una demo en vivo ("esto no lo manda... ah, se mandó"). Test: correr con `PRINT_ONLY=1` y confirmar que NO aparece el log `"Enviando payload a"` y que `/tmp/id_output.txt` no cambia de timestamp.
- **"Agregar al carrito" disparando red:** el catálogo es cosmético por diseño (non-goal: no tocar `/cart/save`); si `addToCart` termina haciendo `fetch`, se infla tráfico falso que confunde la demo de Burp (que debe mostrar SOLO la request del checkout). Test: click en "agregar" sin red observable (revisar que `addToCart` no llama `fetch`/`call`).
- **Regresión del panel de prueba RCE:** `/cart/debug-output` ya está verificado hoy; el rewrite no debe romper ese botón/panel. Test: curl directo al endpoint sigue devolviendo lo mismo pre/post cambio.

---

## Task 1: `exploit.sh` — modo PRINT_ONLY

**Files:**
- Modify: `lab-deserializacion/exploit/exploit.sh:20-63`

**Interfaces:**
- Consumes: nada nuevo — usa las mismas vars `TARGET`, `CMD`, `ENDPOINT`, `JAR`, `PAYLOAD_B64` ya presentes en el script.
- Produces: variable de entorno `PRINT_ONLY` (cualquier valor no vacío la activa). Cuando está activa, el script imprime `PAYLOAD_B64` en stdout, etiquetado, y termina con `exit 0` antes de la sección `curl -X POST`.

- [ ] **Step 1: Agregar la rama `PRINT_ONLY` antes del curl POST**

Insertar, inmediatamente después de la línea que genera `PAYLOAD_B64="$(base64 -w0 /tmp/payload.bin)"` (línea 49 actual) y antes de `echo "[*] Enviando payload a ${TARGET}${ENDPOINT} ..."` (línea 51 actual):

```bash
if [ -n "${PRINT_ONLY:-}" ]; then
    echo ""
    echo "[*] PRINT_ONLY activo: payload generado, NO se envia."
    echo "[*] Pegar este Base64 como body (Content-Type: text/plain) en Burp Repeater,"
    echo "    interceptando una request real a ${TARGET}${ENDPOINT}:"
    echo ""
    echo "${PAYLOAD_B64}"
    exit 0
fi
```

- [ ] **Step 2: Verificar manualmente que el modo normal sigue igual**

Run: `cd lab-deserializacion && docker-compose run --rm exploit http://target-app:8080`
Expected: mismo comportamiento de siempre — fingerprint, envío, respuesta del servidor, sin la línea `PRINT_ONLY activo`.

- [ ] **Step 3: Verificar el modo PRINT_ONLY no envía nada**

Run: `cd lab-deserializacion && docker-compose run --rm -e PRINT_ONLY=1 exploit http://target-app:8080`
Expected: salida termina en el Base64 del payload; NO aparece la línea `"[*] Enviando payload a"`; NO aparece `"[*] Respuesta del servidor"`.

Run adicional (confirma que no hubo RCE de este paso): `curl -s http://127.0.0.1:8080/cart/debug-output` antes y después del comando anterior — el contenido no debe cambiar (seguirá mostrando el resultado del último `id` real que sí se envió, no uno nuevo).

- [ ] **Step 4: Commit**

```bash
git add lab-deserializacion/exploit/exploit.sh
git commit -m "feat: agregar modo PRINT_ONLY a exploit.sh para pegar payload en Burp Repeater"
```

---

## Task 2: Tienda demo en `static/index.html`

**Files:**
- Modify (rewrite completo): `lab-deserializacion/target-app/src/main/resources/static/index.html`

**Interfaces:**
- Consumes: endpoints existentes sin cambios — `GET /cart/health`, `GET /cart/save` (devuelve Base64 de un `Cart` fijo), `POST /cart/restore` (`Content-Type: text/plain`, body = Base64), `POST /cart/restore-filtered` (igual), `GET /cart/debug-output`.
- Produces: página única, sin archivos adicionales. Funciones JS clave (para que quien retome esto después sepa los nombres): `addToCart(name, price)`, `renderCart()`, `checkout(endpoint, boxId)`, `viewDebugOutput()`, `logLine(html)`.

- [ ] **Step 1: Armar el catálogo + carrito cosmético**

HTML: 3 `<div class="product">` (Notebook $850.000, Mouse $12.000, Teclado $35.000), cada uno con botón "Agregar al carrito" que llama `addToCart(name, price)`.

JS: `addToCart(name, price)` empuja `{name, price}` a un array `cartState` en memoria y llama `renderCart()`. `renderCart()` reescribe el `innerHTML` de un `<div id="cart-summary">` con la lista de items + total (`items.reduce`). Ninguna de las dos funciones hace `fetch`.

- [ ] **Step 2: Botones de "ver carrito guardado" (vulnerable y mitigado)**

HTML: sección "Finalizar compra" con dos botones:
- `<button onclick="checkout('/cart/restore', 'result-vuln')">Ver carrito guardado</button>`
- `<button onclick="checkout('/cart/restore-filtered', 'result-safe')">Ver carrito guardado (seguro)</button>`

Cada uno con su `<pre id="result-vuln">`/`<pre id="result-safe">` debajo para la respuesta.

JS: `async function checkout(endpoint, boxId)` — 1) `GET /cart/save` para obtener el Base64 del carrito persistido ("lo que quedó guardado de una compra anterior", simulado); 2) `POST` ese Base64 a `endpoint` con `Content-Type: text/plain`; 3) pinta la respuesta en `#<boxId>` y loguea método+path+status igual que el dashboard viejo (reusar `logLine`). Usar el patrón condicional para la clase CSS (`if (cls) box.classList.add(cls)` — **no** repetir `classList.add('')`).

- [ ] **Step 3: Panel de prueba RCE (reusar lo existente)**

HTML: botón "Ver salida del comando ejecutado" + `<pre id="debug-output">`.
JS: `async function viewDebugOutput()` — `GET /cart/debug-output`, pinta texto crudo en `#debug-output`. Mismo endpoint que el dashboard viejo, sin cambios.

- [ ] **Step 4: Log de actividad (reusar lo existente)**

Reusar `logLine(html)` del dashboard viejo (línea que agrega un row a un `<div id="log">`, con scroll automático) — se llama desde `checkout()` y `viewDebugOutput()` para narrar cada request en vivo.

- [ ] **Step 5: Rebuild, levantar y verificar regresión + feature nueva**

```bash
cd lab-deserializacion
docker-compose build target-app
docker-compose up -d target-app
sleep 5
curl -s http://127.0.0.1:8080/cart/health
curl -s http://127.0.0.1:8080/ | grep -o "Ver carrito guardado" | head -2
```
Expected: health devuelve `vulnlab up`; el grep encuentra las dos variantes del botón (normal + "(seguro)").

Verificación funcional del flujo completo (regresión del ataque, ya probado antes, debe seguir funcionando igual):
```bash
docker-compose run --rm exploit http://target-app:8080
curl -s http://127.0.0.1:8080/cart/debug-output
```
Expected: `uid=0(root) gid=0(root) groups=0(root)` (mismo resultado que la verificación previa).

Abrir `http://127.0.0.1:8080/` en navegador, click manual en "Agregar al carrito" (sin red en la pestaña Network del navegador) y en ambos botones de "ver carrito guardado" (sí debe verse la request en Network/Burp).

- [ ] **Step 6: Commit**

```bash
git add lab-deserializacion/target-app/src/main/resources/static/index.html
git commit -m "feat: reemplazar dashboard por tienda demo narrativa para CWE-502"
```
