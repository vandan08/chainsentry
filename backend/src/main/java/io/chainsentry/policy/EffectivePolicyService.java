package io.chainsentry.policy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Resolves the policy that governs a scan. Precedence: the repo's own
 * {@code chainsentry.yml} (versioned with the code it protects) over the
 * platform defaults. Org-level default policies arrive with the dashboard.
 */
@Service
public class EffectivePolicyService {

    private static final Logger log = LoggerFactory.getLogger(EffectivePolicyService.class);

    private final PolicyParser parser;

    EffectivePolicyService(PolicyParser parser) {
        this.parser = parser;
    }

    public PolicyRules forWorkspace(Path workspace) {
        for (String name : new String[]{"chainsentry.yml", "chainsentry.yaml"}) {
            Path file = workspace.resolve(name);
            if (Files.isRegularFile(file)) {
                try {
                    return parser.parse(Files.readString(file));
                } catch (IOException e) {
                    log.warn("Could not read {}, falling back to default policy", file, e);
                } catch (PolicyValidationException e) {
                    // An invalid policy must not silently weaken the gate.
                    throw e;
                }
            }
        }
        return PolicyRules.defaults();
    }
}
