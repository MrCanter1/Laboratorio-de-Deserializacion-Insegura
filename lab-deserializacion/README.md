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

## Apagar todo

```bash
docker-compose down
```
