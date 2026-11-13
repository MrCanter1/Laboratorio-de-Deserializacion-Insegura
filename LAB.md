# Propuesta de Tema para TPI

**Integrantes:**

- Cantero Santiago — 81658 — 4K3
- Arias Felipe — 82412 — 4K3

## Seguridad en el Desarrollo de Software — UTN FRC

**Tema:** Deserialización Insegura en Java (Insecure Deserialization — CWE-502)

---

## 1. Descripción del tema

La deserialización insegura ocurre cuando una aplicación reconstruye objetos a partir de datos binarios (Java `ObjectInputStream`) sin validar su origen ni su contenido. Si en el classpath existen librerías con clases que encadenan llamadas reflexivas (los llamados *gadget chains*, por ejemplo en versiones vulnerables de Apache Commons-Collections), un atacante puede construir un objeto serializado que, al ser deserializado por el servidor, ejecute código arbitrario (Remote Code Execution) sin explotar ningún bug de memoria ni inyección clásica.

Es una vulnerabilidad real y documentada (forma parte del OWASP Top 10 bajo A08:2021 — Software and Data Integrity Failures, y de múltiples CVEs públicos asociados a Apache Commons-Collections, Jackson, XStream, etc.), pero poco tratada en profundidad en la materia.

## 2. Objetivo del TPI

Construir un laboratorio propio, aislado (Docker, ejecución 100% en localhost), que permita:

1. Entender el mecanismo exacto por el cual deserializar un objeto puede derivar en ejecución de código.
2. Explotar la vulnerabilidad desde dos perspectivas complementarias: **caja negra** (sin acceso al código fuente) y **caja blanca** (con acceso al código fuente).
3. Documentar mitigaciones reales y aplicables.

## 3. Alcance

### Aplicación vulnerable (target)

Aplicación Java (Spring Boot) que simula un caso de uso legítimo: un carrito de compras que se persiste serializado (Base64) en el cliente (patrón real, usado en aplicaciones Java/Java EE antiguas para no depender de sesión en servidor). El endpoint que restaura el carrito deserializa el dato recibido sin validar su procedencia ni su tipo, con una librería vulnerable (Apache Commons-Collections 3.1) en el classpath.

### Enfoque Black Box

Simula un atacante externo, sin acceso al código fuente:

- Identificación de que el dato recibido es un objeto Java serializado (firma de bytes / prefijo Base64 característico).
- Fingerprinting de la librería vulnerable en el classpath.
- Construcción y envío de un payload que dispare ejecución de comandos en el servidor, sin conocer la implementación interna.

### Enfoque White Box

Con el código fuente disponible:

- Revisión de código enfocada en identificar el *sink* vulnerable (`ObjectInputStream.readObject()` sobre datos no confiables).
- Análisis de la cadena de gadgets utilizada: por qué una librería de colecciones termina permitiendo invocar `Runtime.exec()`.
- Comparación entre lo que ve un analista con código fuente (causa raíz, classpath, versión exacta) contra lo que infiere un atacante externo solo por comportamiento.

### Mitigaciones a documentar

- Evitar serialización nativa de Java para datos no confiables; usar formatos con esquema fijo (JSON vía Jackson/Gson con tipos explícitos).
- `ObjectInputFilter` (JEP 290, Java ≥ 9) con listas blancas de clases permitidas.
- Actualización de librerías vulnerables (Commons-Collections ≥ 3.2.2 corrige los gadgets conocidos).
- Principio de menor confianza: nunca deserializar datos que vienen del cliente sin control de integridad (firma/HMAC) y sin restricción de tipos.

## 4. Entorno de laboratorio

- Contenedores Docker aislados, ejecución exclusiva en `localhost` (sin exposición a redes externas).
- Aplicación vulnerable: Java 8, Spring Boot, Apache Commons-Collections 3.1.
- Herramientas de explotación desarrolladas/adaptadas para el laboratorio, documentando el mecanismo interno en el informe.

## 5. Entregables

1. Laboratorio funcional (repositorio con código + instrucciones de levantamiento vía Docker).
2. Informe técnico que cubra:
   - Marco teórico de la vulnerabilidad (CWE-502, OWASP A08:2021).
   - Demostración práctica black box.
   - Demostración práctica white box (análisis de código y de la cadena de gadgets).
   - Mitigaciones y cómo verificarlas.
3. Exposición en clase con demo en vivo del laboratorio.

## 6. Referencias preliminares

- OWASP Top 10 2021 — A08: Software and Data Integrity Failures.
- CWE-502: Deserialization of Untrusted Data.
- Documentación de Apache Commons-Collections — advisories de seguridad asociados a versiones < 3.2.2.
- JEP 290 — Filter Incoming Serialization Data (OpenJDK).
