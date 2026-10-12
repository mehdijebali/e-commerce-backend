package ecommerce.service;

import ecommerce.dto.Purchase;
import ecommerce.dto.PurchaseResponse;

public interface CheckoutService {

    PurchaseResponse placeOrder(Purchase purchase);
}
