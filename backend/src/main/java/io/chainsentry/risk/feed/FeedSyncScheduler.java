package io.chainsentry.risk.feed;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Daily feed refresh, opt-in via {@code chainsentry.feeds.sync-enabled=true}
 * (off by default so dev machines and tests never hit the network). Failures
 * are logged, not rethrown — yesterday's scores beat a dead scheduler.
 */
@Component
@EnableScheduling
@ConditionalOnProperty(name = "chainsentry.feeds.sync-enabled", havingValue = "true")
class FeedSyncScheduler {

    private static final Logger log = LoggerFactory.getLogger(FeedSyncScheduler.class);

    private final FeedSyncService feedSyncService;

    FeedSyncScheduler(FeedSyncService feedSyncService) {
        this.feedSyncService = feedSyncService;
    }

    @Scheduled(cron = "${chainsentry.feeds.sync-cron:0 0 4 * * *}")
    void syncDaily() {
        try {
            feedSyncService.syncKev();
        } catch (Exception e) {
            log.error("KEV feed sync failed", e);
        }
        try {
            feedSyncService.syncEpss();
        } catch (Exception e) {
            log.error("EPSS feed sync failed", e);
        }
    }
}
