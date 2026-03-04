FROM maven:3.9.12-eclipse-temurin-25 AS builder

WORKDIR /app

COPY pom.xml .

RUN mvn dependency:go-offline -B

COPY src ./src

# Package the app, skipping tests (run tests in CI separately)
RUN mvn package -DskipTests -B


FROM eclipse-temurin:25-jre-alpine AS runtime

# Create a non-root user for security (never run as root!)
RUN addgroup --system spring && adduser --system --ingroup spring spring

# Set working directory
WORKDIR /app

# Copy ONLY the final JAR from the builder stage
# Adjust the JAR name to match your artifact (or use a wildcard)
COPY --from=builder /app/target/*.jar app.jar

RUN chown spring:spring app.jar

USER spring

EXPOSE 8080

ENTRYPOINT ["java", \
  "-XX:+UseContainerSupport", \
  "-XX:MaxRAMPercentage=75.0", \
  "-Djava.security.egd=file:/dev/./urandom", \
  "-jar", "app.jar"]