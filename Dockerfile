# =============================================================================
# AuthKit — Multi-stage Docker Build
# Stage 1: Build the Fat JAR with Maven
# Stage 2: Slim JRE runtime image
# =============================================================================

# --- Stage 1: Build ---
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /app

# Copy project definition first (layer caching for dependencies)
COPY pom.xml ./

# Disable Maven 3.9+'s default central-snapshots repository.
# Yubico's webauthn-server-parent uses version ranges [2.13.2.1,3) for Jackson;
# without this, Maven resolves them to SNAPSHOT artifacts that don't fully exist.
RUN mkdir -p /root/.m2 && printf '%s\n' \
    '<?xml version="1.0" encoding="UTF-8"?>' \
    '<settings xmlns="http://maven.apache.org/SETTINGS/1.2.0">' \
    '  <profiles><profile><id>no-snapshots</id>' \
    '    <repositories><repository>' \
    '      <id>central-snapshots</id>' \
    '      <url>https://central.sonatype.com/repository/maven-snapshots</url>' \
    '      <releases><enabled>false</enabled></releases>' \
    '      <snapshots><enabled>false</enabled></snapshots>' \
    '    </repository></repositories>' \
    '  </profile></profiles>' \
    '  <activeProfiles>' \
    '    <activeProfile>no-snapshots</activeProfile>' \
    '  </activeProfiles>' \
    '</settings>' > /root/.m2/settings.xml

RUN mvn dependency:go-offline -B

# Copy source code and build the Fat JAR (skip tests — they run in CI)
COPY src src
RUN mvn clean package -DskipTests -B

# --- Stage 2: Runtime ---
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Create a non-root user for security
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Copy the Fat JAR from the build stage
COPY --from=build /app/target/*.jar app.jar

# Switch to non-root user
USER appuser

# Expose the default Spring Boot port
EXPOSE 8080

# JVM flags for containerized environments
ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]
