package io.chainsentry;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan
public class ChainSentryApplication {

    public static void main(String[] args) {
        SpringApplication.run(ChainSentryApplication.class, args);
    }
}
