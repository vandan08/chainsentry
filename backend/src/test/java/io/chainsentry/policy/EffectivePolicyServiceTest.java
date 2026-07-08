package io.chainsentry.policy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EffectivePolicyServiceTest {

    private final EffectivePolicyService service = new EffectivePolicyService(new PolicyParser());

    @Test
    void workspaceWithoutPolicyFileGetsDefaults(@TempDir Path workspace) {
        assertThat(service.forWorkspace(workspace)).isEqualTo(PolicyRules.defaults());
    }

    @Test
    void repoPolicyFileWins(@TempDir Path workspace) throws IOException {
        Files.writeString(workspace.resolve("chainsentry.yml"), """
                gate:
                  fail-on-kev: false
                """);

        assertThat(service.forWorkspace(workspace).failOnKev()).isFalse();
    }

    @Test
    void invalidPolicyFileFailsLoudlyRatherThanWeakeningTheGate(@TempDir Path workspace) throws IOException {
        Files.writeString(workspace.resolve("chainsentry.yml"), "gate:\n  fail-risk-threshold: 7");

        assertThatThrownBy(() -> service.forWorkspace(workspace))
                .isInstanceOf(PolicyValidationException.class);
    }
}
