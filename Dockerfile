# =============================================================================
# AuthKit — Multi-stage Docker Build
# Stage 1: Build the Fat JAR with Maven
# Stage 2: Slim JRE runtime image
# =============================================================================

# --- Stage 1: Build ---
FROM maven:3.9-eclipse-temurin-17-alpine AS build
WORKDIR /app

# Copy project definition first (layer caching for dependencies)
COPY pom.xml ./
RUN mvn dependency:go-offline -B

# Copy source code and build the Fat JAR (skip tests — they run in CI)
COPY src src
RUN mvn clean package -DskipTests -B

# --- Stage 2: Runtime ---
FROM eclipse-temurin:17-jre-alpine
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
