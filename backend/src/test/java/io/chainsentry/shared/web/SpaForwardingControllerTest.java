package io.chainsentry.shared.web;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.forwardedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Deep links into the SPA only break in production — a dev server rewrites
 * them for free — so the forwarding is pinned here instead of being discovered
 * by someone sharing a scan link.
 */
@WebMvcTest(SpaForwardingController.class)
class SpaForwardingControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    @DisplayName("client routes forward to the SPA shell")
    void forwardsClientRoutes() throws Exception {
        for (String path : new String[]{
                "/app",
                "/orgs/6f1a0b2c-1111-4a00-9000-000000000001/overview",
                "/repos/6f1a0b2c-2222-4a00-9000-000000000002",
                "/scans/6f1a0b2c-3333-4a00-9000-000000000005"}) {
            mockMvc.perform(get(path))
                    .andExpect(status().isOk())
                    .andExpect(forwardedUrl("/index.html"));
        }
    }

    @Test
    @DisplayName("an unknown path still 404s rather than silently rendering the app")
    void doesNotSwallowUnknownPaths() throws Exception {
        mockMvc.perform(get("/nope")).andExpect(status().isNotFound());
    }
}
