package io.chainsentry.shared.web;

import io.chainsentry.shared.config.ChainSentryProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Set;

/**
 * Guards the public demo deployment: the seeded world is the whole point of
 * that instance, so anything that would mutate it is refused before it reaches
 * a controller. Reads stay fully open — visitors get the real API, not a mock.
 *
 * <p>Only registered when {@code chainsentry.demo.read-only} is true, so a
 * normal deployment carries no request-path cost at all.
 */
@Component
@ConditionalOnProperty(prefix = "chainsentry.demo", name = "read-only")
class ReadOnlyModeFilter extends OncePerRequestFilter {

    private static final Set<String> SAFE_METHODS = Set.of("GET", "HEAD", "OPTIONS");

    private final boolean readOnly;

    ReadOnlyModeFilter(ChainSentryProperties properties) {
        this.readOnly = properties.demo() != null && properties.demo().readOnly();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        if (readOnly && !SAFE_METHODS.contains(request.getMethod())) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
            response.getWriter().write("""
                    {"type":"about:blank","title":"Forbidden","status":403,\
                    "detail":"This is a read-only demo instance — %s requests are disabled. \
                    Run it locally to exercise the write paths (scan triggers, suppressions, fix-PRs)."}\
                    """.formatted(request.getMethod()));
            return;
        }
        chain.doFilter(request, response);
    }
}
