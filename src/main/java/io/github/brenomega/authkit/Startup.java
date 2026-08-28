package io.github.brenomega.authkit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.scheduling.annotation.EnableScheduling;

/** Starts AuthKit with external configuration binding and scheduled maintenance enabled. */
@SpringBootApplication
@ConfigurationPropertiesScan
@EnableScheduling
public class Startup {

    public static void main(String[] args) {
        SpringApplication.run(Startup.class, args);
    }

}
