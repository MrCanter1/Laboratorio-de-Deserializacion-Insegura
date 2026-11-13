package com.tpi.vulnlab;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * TPI - Seguridad en el Desarrollo de Software (UTN FRC).
 * Aplicacion target deliberadamente vulnerable a Deserializacion Insegura
 * (CWE-502 / OWASP A08:2021). Uso exclusivamente academico, en Docker aislado.
 */
@SpringBootApplication
public class VulnLabApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnLabApplication.class, args);
    }
}
