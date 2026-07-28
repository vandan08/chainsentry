# API-only image — no dashboard. This is what docker-compose and local
# container runs use. For deployment, build the root ../Dockerfile instead:
# it compiles the React dashboard into this jar's static resources so the SPA
# and the API share one origin. See docs/11-DEPLOYMENT.md.

# Build stage
FROM maven:3.9-eclipse-temurin-24 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q dependency:go-offline
COPY src ./src
RUN mvn -q -DskipTests package

# Runtime stage
FROM eclipse-temurin:24-jre
RUN useradd --system --uid 1001 chainsentry
USER chainsentry
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
