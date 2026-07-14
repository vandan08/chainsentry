package io.chainsentry.github.webhook;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.UUID;

/** One received webhook delivery — the unique {@code deliveryId} is the redelivery dedup key. */
@Entity
@Table(name = "webhook_delivery")
public class WebhookDelivery {

    @Id
    private UUID id;

    @Column(name = "delivery_id", nullable = false, unique = true)
    private String deliveryId;

    @Column(nullable = false)
    private String event;

    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;

    protected WebhookDelivery() {
        // JPA
    }

    public WebhookDelivery(String deliveryId, String event) {
        this.id = UUID.randomUUID();
        this.deliveryId = deliveryId;
        this.event = event;
        this.receivedAt = Instant.now();
    }

    public String deliveryId() {
        return deliveryId;
    }

    public String event() {
        return event;
    }
}
