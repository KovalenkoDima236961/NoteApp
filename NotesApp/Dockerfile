FROM openjdk:21-jdk-slim
LABEL authors="Dima"

WORKDIR /app

COPY target/notes-0.0.1-SNAPSHOT.jar /app/note-app.jar

EXPOSE 8080


CMD ["java", "-jar", "note-app.jar"]