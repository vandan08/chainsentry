package io.chainsentry.remediation;

import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Deterministic, surgical version bumps in dependency manifests — no LLM in
 * this path on purpose: the edit is mechanical, so it's done mechanically.
 * Only whitelisted manifest types are ever touched, and only the one version
 * string of the affected package changes.
 */
@Component
class ManifestPatcher {

    static final Set<String> SUPPORTED_MANIFESTS = Set.of("pom.xml", "package.json");

    /**
     * @return the patched manifest, or empty when the package/version pair
     *         can't be located unambiguously (never guesses)
     */
    Optional<String> patch(String manifestName, String content, String purl,
                           String installedVersion, String fixedVersion) {
        if (installedVersion == null || fixedVersion == null || purl == null) {
            return Optional.empty();
        }
        return switch (manifestName) {
            case "pom.xml" -> patchPom(content, purl, installedVersion, fixedVersion);
            case "package.json" -> patchPackageJson(content, purl, installedVersion, fixedVersion);
            default -> Optional.empty();
        };
    }

    /** {@code <artifactId>x</artifactId> … <version>old</version>} within one dependency block. */
    private Optional<String> patchPom(String content, String purl, String installed, String fixed) {
        String artifactId = artifactFromPurl(purl);
        if (artifactId == null) {
            return Optional.empty();
        }
        Pattern pattern = Pattern.compile(
                "(<artifactId>\\s*" + Pattern.quote(artifactId) + "\\s*</artifactId>"
                        + "(?:(?!</dependency>|<artifactId>).)*?<version>\\s*)"
                        + Pattern.quote(installed)
                        + "(\\s*</version>)",
                Pattern.DOTALL);
        return replaceExactlyOnce(pattern, content, fixed);
    }

    /** {@code "name": "^old"} — the range prefix (^ ~) is preserved. */
    private Optional<String> patchPackageJson(String content, String purl, String installed, String fixed) {
        String packageName = npmNameFromPurl(purl);
        if (packageName == null) {
            return Optional.empty();
        }
        Pattern pattern = Pattern.compile(
                "(\"" + Pattern.quote(packageName) + "\"\\s*:\\s*\"[~^]?)"
                        + Pattern.quote(installed)
                        + "(\")");
        return replaceExactlyOnce(pattern, content, fixed);
    }

    /** Zero matches = can't act; two matches = ambiguous. Both mean "don't touch the file". */
    private Optional<String> replaceExactlyOnce(Pattern pattern, String content, String fixed) {
        Matcher matcher = pattern.matcher(content);
        if (!matcher.find()) {
            return Optional.empty();
        }
        int start = matcher.start();
        String patched = new StringBuilder(content)
                .replace(matcher.start(), matcher.end(), matcher.group(1) + fixed + matcher.group(2))
                .toString();
        if (pattern.matcher(content).find(matcher.end())) {
            return Optional.empty(); // second occurrence — refuse to guess which one
        }
        return Optional.of(patched);
    }

    private String artifactFromPurl(String purl) {
        // pkg:maven/group/artifact@version
        if (!purl.startsWith("pkg:maven/")) {
            return null;
        }
        String coordinates = purl.substring("pkg:maven/".length());
        int at = coordinates.lastIndexOf('@');
        if (at >= 0) {
            coordinates = coordinates.substring(0, at);
        }
        int slash = coordinates.lastIndexOf('/');
        return slash >= 0 ? coordinates.substring(slash + 1) : null;
    }

    private String npmNameFromPurl(String purl) {
        // pkg:npm/name@version or pkg:npm/%40scope/name@version
        if (!purl.startsWith("pkg:npm/")) {
            return null;
        }
        String name = purl.substring("pkg:npm/".length());
        int at = name.lastIndexOf('@');
        if (at > 0) {
            name = name.substring(0, at);
        }
        return name.replace("%40", "@");
    }
}
