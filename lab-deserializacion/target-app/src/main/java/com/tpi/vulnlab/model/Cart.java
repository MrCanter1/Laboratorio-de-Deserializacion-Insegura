package com.tpi.vulnlab.model;

import java.io.Serializable;
import java.util.List;

public class Cart implements Serializable {

    private static final long serialVersionUID = 1L;

    private List<CartItem> items;

    public Cart() {
    }

    public Cart(List<CartItem> items) {
        this.items = items;
    }

    public List<CartItem> getItems() {
        return items;
    }

    public void setItems(List<CartItem> items) {
        this.items = items;
    }
}
