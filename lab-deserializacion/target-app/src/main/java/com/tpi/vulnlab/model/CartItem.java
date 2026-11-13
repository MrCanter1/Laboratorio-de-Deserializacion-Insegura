package com.tpi.vulnlab.model;

import java.io.Serializable;

/**
 * Item de un carrito de compras. Implementa Serializable porque el carrito
 * completo se persiste del lado del cliente como objeto Java serializado
 * (patron real usado en apps Java/Java EE antiguas para no depender de
 * sesion en servidor).
 */
public class CartItem implements Serializable {

    private static final long serialVersionUID = 1L;

    private String productName;
    private double price;
    private int quantity;

    public CartItem() {
    }

    public CartItem(String productName, double price, int quantity) {
        this.productName = productName;
        this.price = price;
        this.quantity = quantity;
    }

    public String getProductName() {
        return productName;
    }

    public void setProductName(String productName) {
        this.productName = productName;
    }

    public double getPrice() {
        return price;
    }

    public void setPrice(double price) {
        this.price = price;
    }

    public int getQuantity() {
        return quantity;
    }

    public void setQuantity(int quantity) {
        this.quantity = quantity;
    }

    @Override
    public String toString() {
        return "CartItem{productName='" + productName + "', price=" + price + ", quantity=" + quantity + "}";
    }
}
