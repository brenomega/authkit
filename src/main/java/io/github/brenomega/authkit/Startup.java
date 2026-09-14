package io.github.brenomega.authkit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/** Starts AuthKit with external configuration binding and scheduled maintenance enabled. */
@SpringBootApplication
@ConfigurationPropertiesScan
public class Startup {

    public static void main(String[] args) {
        SpringApplication.run(Startup.class, args);
    }

}
