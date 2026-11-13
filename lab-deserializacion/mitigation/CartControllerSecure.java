package com.tpi.vulnlab.controller;

// ============================================================================
// REFERENCIA PARA EL INFORME - NO esta en el build del target-app.
//
// Version corregida del endpoint /cart/restore, para documentar la
// mitigacion y poder compararla contra el sink vulnerable de
// CartController.java. Pensada para pegar en el informe o, si se quiere
// demostrar en vivo, copiarla al modulo target-app, agregarla al pom.xml
// (requiere Java >= 9 para ObjectInputFilter.Config.createFilter en el
// classpath base; alternativamente usar el filtro programatico via
// ObjectInputStream#setObjectInputFilter en Java 9+) y levantar un segundo
// contenedor "target-app-fixed".
// ============================================================================

import com.tpi.vulnlab.model.Cart;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

public class CartControllerSecure {

    /**
     * MITIGACION 1 (preferida): no usar serializacion nativa de Java para
     * datos que van y vuelven del cliente. Usar JSON (Jackson) con un tipo
     * explicito -> no hay readObject(), no hay gadget chain posible.
     *
     * El cliente manda {"items":[{"productName":"Mouse","price":12000,"quantity":2}]}
     * y Jackson lo mapea directo a Cart. No hay forma de "inyectar" una clase
     * arbitraria: Jackson instancia exactamente el tipo declarado.
     */
    @PostMapping("/restore-json")
    public String restoreJson(@RequestBody Cart cart) {
        return "Carrito restaurado (JSON) con " + cart.getItems().size() + " items";
    }

    /**
     * MITIGACION 2: si por algun motivo hay que mantener Java serialization
     * (legacy), usar JEP 290 / ObjectInputFilter (Java >= 9, API real -- NO
     * disponible en OpenJDK 8, verificado al implementar este laboratorio:
     * java.io.ObjectInputFilter no existe en Temurin 8, ni en build ni en
     * runtime; es exclusivo de Java 9+ o de builds propietarios de Oracle)
     * con whitelist explicita de clases permitidas. En este laboratorio,
     * como el target corre Java 8, se implemento el equivalente real y
     * probado con resolveClass() -- ver target-app/.../security/WhitelistObjectInputStream.java.
     * Cualquier clase fuera de la whitelist (p. ej.
     * org.apache.commons.collections.functors.InvokerTransformer) se
     * rechaza ANTES de resolverse/instanciarse.
     */
    @PostMapping(value = "/restore-filtered", consumes = "text/plain")
    public String restoreFiltered(@RequestBody String base64Payload) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Payload.trim());

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                // Whitelist estricta: solo las clases que el carrito necesita.
                ois.setObjectInputFilter(filterInfo -> {
                    Class<?> clazz = filterInfo.serialClass();
                    if (clazz == null) {
                        return ObjectInputFilter.Status.UNDECIDED;
                    }
                    String name = clazz.getName();
                    boolean allowed = name.equals("com.tpi.vulnlab.model.Cart")
                            || name.equals("com.tpi.vulnlab.model.CartItem")
                            || name.equals("java.util.ArrayList")
                            || name.equals("java.lang.String")
                            || clazz.isArray();
                    return allowed ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED;
                });

                Object obj = ois.readObject();
                Cart cart = (Cart) obj;
                return "Carrito restaurado (filtrado) con " + cart.getItems().size() + " items";
            }
        } catch (InvalidClassException e) {
            // Esto es lo que se ve cuando el filtro bloquea, por ejemplo,
            // un payload CommonsCollections1: la clase no esta en la whitelist.
            return "Rechazado por ObjectInputFilter: " + e.getMessage();
        } catch (Exception e) {
            return "Error al restaurar carrito: " + e.getMessage();
        }
    }

    /**
     * MITIGACION 3 (defensa en profundidad, no sustituye a 1/2):
     * si de verdad hay que aceptar datos serializados del cliente, firmarlos
     * con HMAC usando una clave que solo el servidor conoce, y verificar la
     * firma ANTES de llamar a readObject(). Esto no evita el RCE si la
     * clave se filtra, pero cierra el caso de un atacante externo sin ella.
     *
     * byte[] mac = hmacSha256(secretKey, serializedBytes);
     * if (!constantTimeEquals(mac, macRecibido)) throw new SecurityException();
     *
     * MITIGACION 4 (higiene de dependencias): actualizar commons-collections
     * a >= 3.2.2 (corrige InvokerTransformer para que no sea explotable
     * "out of the box"), y en general correr un SCA (OWASP Dependency-Check,
     * Snyk, etc.) para detectar librerias con gadgets conocidos.
     */
    private CartControllerSecure() {
    }
}
