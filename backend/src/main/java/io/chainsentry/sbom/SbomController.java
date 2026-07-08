package io.chainsentry.sbom;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1")
class SbomController {

    private static final MediaType CYCLONEDX_JSON = MediaType.parseMediaType("application/vnd.cyclonedx+json");

    private final SbomService sbomService;

    SbomController(SbomService sbomService) {
        this.sbomService = sbomService;
    }

    @GetMapping("/scans/{scanId}/sbom")
    ResponseEntity<String> sbom(@PathVariable UUID scanId) {
        String document = sbomService.document(scanId)
                .orElseThrow(() -> new SbomNotFoundException(scanId));
        return ResponseEntity.ok().contentType(CYCLONEDX_JSON).body(document);
    }

    /** The PR supply-chain delta: what changed between two scans, annotated with risk. */
    @GetMapping("/sboms/diff")
    SbomDiff diff(@RequestParam UUID base, @RequestParam UUID head) {
        return sbomService.diff(base, head);
    }
}
