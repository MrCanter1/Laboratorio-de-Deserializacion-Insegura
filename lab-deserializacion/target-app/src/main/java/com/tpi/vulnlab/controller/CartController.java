package com.tpi.vulnlab.controller;

import com.tpi.vulnlab.model.Cart;
import com.tpi.vulnlab.model.CartItem;
import com.tpi.vulnlab.security.WhitelistObjectInputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Base64;

/**
 * Endpoint que simula el patron "carrito persistido del lado del cliente":
 * el servidor serializa el carrito a Base64 y lo devuelve; el cliente lo
 * manda de vuelta mas tarde para "restaurarlo", y el servidor lo deserializa.
 *
 * VULNERABILIDAD (CWE-502 / OWASP A08:2021):
 * /cart/restore deserializa el Base64 recibido con ObjectInputStream.readObject()
 * SIN validar origen, firma/HMAC ni tipo esperado. Como Apache Commons-Collections
 * 3.1 esta en el classpath, un atacante puede enviar un payload de tipo
 * CommonsCollections1 (ysoserial) y lograr ejecucion de comandos en el servidor,
 * sin que el endpoint espere jamas recibir nada distinto de un Cart.
 */
@RestController
@RequestMapping("/cart")
public class CartController {

    private static final Logger log = LoggerFactory.getLogger(CartController.class);

    @GetMapping("/health")
    public String health() {
        return "vulnlab up";
    }

    /**
     * Flujo legitimo: arma un carrito de ejemplo y lo devuelve serializado
     * en Base64, tal como lo haria la app real para persistirlo en el cliente.
     */
    @GetMapping("/save")
    public String save() throws Exception {
        Cart cart = new Cart(Arrays.asList(
                new CartItem("Notebook", 850000.0, 1),
                new CartItem("Mouse", 12000.0, 2)
        ));

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(cart);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    /**
     * SINK VULNERABLE.
     * Recibe un string Base64 (Content-Type: text/plain) y lo deserializa
     * directamente, sin ObjectInputFilter, sin whitelist de clases, sin
     * verificar firma/HMAC del dato. Este es el punto exacto que el white box
     * debe senalar como causa raiz, y el que el black box debe inferir desde
     * afuera (firma de bytes 0xACED del serializado Java, o prefijo "rO0" en Base64).
     */
    @PostMapping(value = "/restore", consumes = "text/plain")
    public String restore(@RequestBody String base64Payload) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Payload.trim());

            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
                Object obj = ois.readObject(); // <-- sink: deserializa dato no confiable

                if (obj instanceof Cart) {
                    Cart cart = (Cart) obj;
                    log.info("Carrito restaurado: {}", cart.getItems());
                    return "Carrito restaurado con " + cart.getItems().size() + " items";
                }
                return "Objeto deserializado de tipo inesperado: " + obj.getClass().getName();
            }
        } catch (Exception e) {
            log.warn("Error al restaurar carrito: {}", e.toString());
            return "Error al restaurar carrito: " + e.getMessage();
        }
    }

    /**
     * MITIGACION aplicada y probada: whitelist de clases via
     * WhitelistObjectInputStream (override de resolveClass()). Mismo
     * formato de entrada que /restore (Base64 de un objeto serializado),
     * pero cualquier clase fuera de la whitelist -- como las de la gadget
     * chain de commons-collections -- se rechaza ANTES de instanciarse,
     * sin llegar a ejecutar nada.
     */
    @PostMapping(value = "/restore-filtered", consumes = "text/plain")
    public String restoreFiltered(@RequestBody String base64Payload) {
        try {
            byte[] data = Base64.getDecoder().decode(base64Payload.trim());

            try (ObjectInputStream ois = new WhitelistObjectInputStream(new ByteArrayInputStream(data))) {
                Object obj = ois.readObject();
                if (obj instanceof Cart) {
                    Cart cart = (Cart) obj;
                    log.info("Carrito restaurado (filtrado): {}", cart.getItems());
                    return "Carrito restaurado (filtrado) con " + cart.getItems().size() + " items";
                }
                return "Objeto deserializado de tipo inesperado: " + obj.getClass().getName();
            }
        } catch (InvalidClassException e) {
            log.warn("Rechazado por ObjectInputFilter: {}", e.toString());
            return "Rechazado por ObjectInputFilter: " + e.getMessage();
        } catch (Exception e) {
            log.warn("Error al restaurar carrito (filtrado): {}", e.toString());
            return "Error al restaurar carrito: " + e.getMessage();
        }
    }
}
