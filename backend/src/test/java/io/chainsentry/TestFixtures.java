package io.chainsentry;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;

/** Loads classpath fixtures (the demo profile's recorded reports double as golden files). */
public final class TestFixtures {

    private TestFixtures() {
    }

    public static String read(String resource) {
        try (InputStream in = TestFixtures.class.getClassLoader().getResourceAsStream(resource)) {
            if (in == null) {
                throw new IllegalArgumentException("Fixture not on classpath: " + resource);
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
