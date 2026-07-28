# Deployment image: the whole product in one container.
#
# The dashboard is compiled and baked into the jar's static resources, so the
# SPA and the API share an origin — no CORS, no second deployment, one URL.
# (backend/Dockerfile builds the API alone, which is what docker-compose uses.)
#
#   docker build -t chainsentry .
#   docker run -p 8080:8080 -e SPRING_PROFILES_ACTIVE=prod,demo \
#              -e DATABASE_URL=postgres://user:pass@host:5432/chainsentry chainsentry

# ── Stage 1: dashboard ──────────────────────────────────────────────────────
FROM node:22-alpine AS web
WORKDIR /web
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

# ── Stage 2: backend (with the dashboard as a static resource) ──────────────
FROM maven:3.9-eclipse-temurin-24 AS api
WORKDIR /app
# Dependencies resolve in their own layer so source edits don't re-download Maven Central.
COPY backend/pom.xml .
RUN mvn -q -B dependency:go-offline
COPY backend/src ./src
# Overwrites the no-build-step dashboard shipped in the repo with the compiled SPA.
COPY --from=web /web/dist/ ./src/main/resources/static/
RUN mvn -q -B -DskipTests package

# ── Stage 3: runtime ────────────────────────────────────────────────────────
FROM eclipse-temurin:24-jre
RUN useradd --system --uid 1001 chainsentry
WORKDIR /app
COPY --from=api /app/target/*.jar app.jar
USER chainsentry
EXPOSE 8080

# MaxRAMPercentage matters on 512 MB free tiers: without it the JVM sizes the
# heap off the host's memory, not the container's, and gets OOM-killed.
ENV JAVA_OPTS="-XX:MaxRAMPercentage=70 -XX:+UseSerialGC"
ENTRYPOINT ["sh", "-c", "exec java $JAVA_OPTS -jar app.jar"]
