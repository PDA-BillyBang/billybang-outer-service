FROM openjdk:17
ARG JAR_FILE=target/*.jar
VOLUME /tmp
COPY ${JAR_FILE} billybang-discovery-service.jar
EXPOSE 8761
ENTRYPOINT ["java", "-jar", "/billybang-discovery-service.jar"]