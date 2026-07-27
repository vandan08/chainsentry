package io.chainsentry.shared.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * The dashboard is a client-side-routed SPA served from the same origin as the
 * API. A hard refresh (or a shared link) on a client route reaches the server,
 * which has no such mapping and would answer 404 — so the known client routes
 * forward to the SPA shell and let the router take it from there.
 *
 * <p>Deliberately an explicit list rather than a catch-all: an unknown path
 * should still 404 instead of silently rendering the app.
 */
@Controller
class SpaForwardingController {

    @GetMapping({"/app", "/orgs/**", "/repos/**", "/scans/**"})
    String forwardToShell() {
        return "forward:/index.html";
    }
}
