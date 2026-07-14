package io.chainsentry.github.webhook;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

/**
 * GitHub App webhook ingress. Order is deliberate: verify the HMAC against
 * the raw body before parsing anything, dedupe on the delivery GUID (GitHub
 * redelivers), then hand off — always answering inside GitHub's 10s window.
 */
@RestController
public class WebhookController {

    private static final Logger log = LoggerFactory.getLogger(WebhookController.class);

    private final WebhookSignatureVerifier verifier;
    private final WebhookDeliveryRepository deliveries;
    private final WebhookEventHandler handler;

    WebhookController(WebhookSignatureVerifier verifier, WebhookDeliveryRepository deliveries,
                      WebhookEventHandler handler) {
        this.verifier = verifier;
        this.deliveries = deliveries;
        this.handler = handler;
    }

    @PostMapping("/webhooks/github")
    ResponseEntity<Void> receive(@RequestBody String rawBody,
                                 @RequestHeader(value = "X-Hub-Signature-256", required = false) String signature,
                                 @RequestHeader("X-GitHub-Event") String event,
                                 @RequestHeader("X-GitHub-Delivery") String deliveryId) {
        try {
            if (!verifier.matches(rawBody, signature)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
            }
        } catch (IllegalStateException notConfigured) {
            log.warn(notConfigured.getMessage());
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).build();
        }
        if (!recordDelivery(deliveryId, event)) {
            return ResponseEntity.ok().build(); // redelivery — acknowledged, not reprocessed
        }
        handler.handle(event, rawBody);
        return ResponseEntity.accepted().build();
    }

    /** The unique constraint on delivery_id settles races between concurrent redeliveries. */
    private boolean recordDelivery(String deliveryId, String event) {
        if (deliveries.existsByDeliveryId(deliveryId)) {
            return false;
        }
        try {
            deliveries.save(new WebhookDelivery(deliveryId, event));
            return true;
        } catch (DataIntegrityViolationException raced) {
            return false;
        }
    }
}
