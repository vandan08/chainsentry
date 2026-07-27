package io.chainsentry.shared.web;

import io.chainsentry.shared.config.ChainSentryProperties;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * The public instance is a portfolio link. If this filter regresses, the first
 * person to POST can rewrite the demo for everyone who visits after them.
 */
class ReadOnlyModeFilterTest {

    private static ReadOnlyModeFilter filter(boolean readOnly) {
        return new ReadOnlyModeFilter(new ChainSentryProperties(null, null, null, null,
                new ChainSentryProperties.Demo(readOnly)));
    }

    private static MockHttpServletResponse dispatch(ReadOnlyModeFilter filter, String method, FilterChain chain)
            throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest(method, "/api/v1/repos/x/scans");
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(request, response, chain);
        return response;
    }

    @Test
    @DisplayName("reads pass through untouched")
    void allowsReads() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        MockHttpServletResponse response = dispatch(filter(true), "GET", chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        verify(chain).doFilter(any(), any());
    }

    @Test
    @DisplayName("writes are refused with a 403 problem detail and never reach a controller")
    void refusesWrites() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        MockHttpServletResponse response = dispatch(filter(true), "POST", chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(response.getContentType()).isEqualTo("application/problem+json");
        assertThat(response.getContentAsString()).contains("read-only demo instance");
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("DELETE is refused too, not just POST")
    void refusesEveryUnsafeMethod() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        assertThat(dispatch(filter(true), "DELETE", chain).getStatus())
                .isEqualTo(HttpStatus.FORBIDDEN.value());
        assertThat(dispatch(filter(true), "PATCH", chain).getStatus())
                .isEqualTo(HttpStatus.FORBIDDEN.value());
        verify(chain, never()).doFilter(any(), any());
    }

    @Test
    @DisplayName("with the guard off, writes proceed as normal")
    void allowsWritesWhenDisabled() throws Exception {
        FilterChain chain = mock(FilterChain.class);

        MockHttpServletResponse response = dispatch(filter(false), "POST", chain);

        assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
        verify(chain).doFilter(any(), any());
    }
}
