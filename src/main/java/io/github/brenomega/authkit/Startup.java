package io.github.brenomega.authkit;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * Entry point for the AuthKit application.
 *
 * <p>This class bootstraps the Spring Boot context, initializing all
 * auto-configured beans, security filters, and infrastructure adapters
 * defined across the application packages.</p>
 *
 * <p>The application is designed to run as a stateless, containerized
 * service behind a reverse proxy (DT 3.1.17, DT 3.2.5).</p>
 *
 * @author Breno Alvarenga
 * @see org.springframework.boot.autoconfigure.SpringBootApplication
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class Startup {

	/**
	 * Application entry point.
	 *
	 * @param args command-line arguments passed to the Spring Boot runtime
	 */
	public static void main(String[] args) {
		SpringApplication.run(Startup.class, args);
	}

}
