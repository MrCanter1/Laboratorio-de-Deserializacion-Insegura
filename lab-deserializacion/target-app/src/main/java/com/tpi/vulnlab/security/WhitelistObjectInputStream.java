package com.tpi.vulnlab.security;

import java.io.IOException;
import java.io.InputStream;
import java.io.InvalidClassException;
import java.io.ObjectInputStream;
import java.io.ObjectStreamClass;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * MITIGACION aplicada (whitelist de clases via resolveClass()).
 *
 * java.io.ObjectInputFilter (JEP 290) solo existe desde Java 9; OpenJDK 8
 * (Temurin incluido) NO lo tiene -- el backport con esa API es exclusivo de
 * builds propietarios de Oracle. Por eso esta mitigacion usa la tecnica
 * clasica, disponible desde Java 5: subclasear ObjectInputStream y
 * sobrescribir resolveClass(), que se invoca para CADA clase que el stream
 * necesita resolver, ANTES de instanciarla.
 *
 * Si una clase no esta en la whitelist -- por ejemplo cualquiera de
 * org.apache.commons.collections.functors.* o
 * org.apache.commons.collections.map.LazyMap, usadas por las gadget chains
 * de ysoserial -- se lanza InvalidClassException ahi mismo, antes de que
 * el objeto se construya y antes de que cualquier metodo de esa clase
 * (como InvokerTransformer.transform(), que termina llamando
 * Runtime.exec()) pueda ejecutarse.
 */
public class WhitelistObjectInputStream extends ObjectInputStream {

    private static final Set<String> ALLOWED_CLASSES = new HashSet<>(Arrays.asList(
            "com.tpi.vulnlab.model.Cart",
            "com.tpi.vulnlab.model.CartItem",
            "java.util.Arrays$ArrayList",
            "java.util.ArrayList",
            "java.lang.String",
            "[Lcom.tpi.vulnlab.model.CartItem;"
    ));

    public WhitelistObjectInputStream(InputStream in) throws IOException {
        super(in);
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        String name = desc.getName();
        if (!ALLOWED_CLASSES.contains(name)) {
            throw new InvalidClassException(name, "Clase no permitida por whitelist de deserializacion");
        }
        return super.resolveClass(desc);
    }
}
