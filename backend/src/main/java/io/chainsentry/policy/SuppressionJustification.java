package io.chainsentry.policy;

/** Why a finding is suppressed — constrained so every suppression is auditable. */
public enum SuppressionJustification {
    NOT_AFFECTED, FALSE_POSITIVE, MITIGATED, ACCEPTED_RISK
}
