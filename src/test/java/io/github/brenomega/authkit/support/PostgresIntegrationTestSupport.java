package io.github.brenomega.authkit.support;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.utility.DockerImageName;

/** Supplies an actual PostgreSQL 17 database to service-level integration tests. */
public abstract class PostgresIntegrationTestSupport {

    @SuppressWarnings("resource")
    @Container
    protected static final PostgreSQLContainer<?> POSTGRES =
            new PostgreSQLContainer<>(DockerImageName.parse(
                    "postgres:17-alpine@sha256:778d0b486d6daa02b77434d0358ec57a1b21fd8b6d22ac2eef56a33e816928f6")
                    .asCompatibleSubstituteFor("postgres"));

    @DynamicPropertySource
    static void postgresProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
        registry.add("spring.datasource.username", POSTGRES::getUsername);
        registry.add("spring.datasource.password", POSTGRES::getPassword);
        registry.add("spring.datasource.driver-class-name", () -> "org.postgresql.Driver");
        registry.add("spring.jpa.database-platform", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.properties.hibernate.dialect", () -> "org.hibernate.dialect.PostgreSQLDialect");
        registry.add("spring.jpa.properties.hibernate.jdbc.lob.non_contextual_creation", () -> "true");
        registry.add("spring.jpa.hibernate.ddl-auto", () -> "create-drop");
        registry.add("spring.flyway.enabled", () -> "false");
    }
}
