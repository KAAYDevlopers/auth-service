FROM amazoncorretto:17
COPY target/*.jar auth-service-0.0.1.jar
EXPOSE 8084
ENTRYPOINT ["java","-jar", "auth-service-0.0.1.jar"]
ENV SPRING_CONFIG_LOCATION=file:/app/config/
