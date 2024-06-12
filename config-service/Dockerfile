FROM openjdk:17
ARG JAR_FILE=target/*.jar
VOLUME /tmp
COPY ${JAR_FILE} billybang-config-service.jar
EXPOSE 8888
ENTRYPOINT ["java", "-jar", "/billybang-config-service.jar"]