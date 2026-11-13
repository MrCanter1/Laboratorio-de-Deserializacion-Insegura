# --- build stage ---
# eclipse-temurin:8-jdk trae JDK 8u512 (incluye el backport de ObjectInputFilter
# usado por la mitigacion). La imagen "maven:3.8-eclipse-temurin-8" trae un JDK
# 8u392 mas viejo que NO tiene esa clase, por eso se instala Maven a mano aca.
FROM eclipse-temurin:8-jdk AS build
RUN apt-get update && apt-get install -y --no-install-recommends maven \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn -q -DskipTests package

# --- run stage ---
FROM eclipse-temurin:8-jre
WORKDIR /app
COPY --from=build /app/target/vulnlab.jar ./vulnlab.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "vulnlab.jar"]
