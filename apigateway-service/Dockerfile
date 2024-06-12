FROM openjdk:17
ARG JAR_FILE=target/*.jar
VOLUME /tmp
COPY ${JAR_FILE} billybang-apigateway-service.jar
EXPOSE 8000
ENTRYPOINT ["java", "-jar", "/billybang-apigateway-service.jar"]