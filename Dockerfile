# 1단계: Gradle을 사용하여 애플리케이션 빌드
FROM gradle:8.8-jdk21 AS build
WORKDIR /home/gradle/src
COPY . .
RUN gradle build --no-daemon -x test

# 2단계: 빌드된 JAR 파일로 실행용 이미지 생성
FROM eclipse-temurin:21-jre-jammy
WORKDIR /app
COPY --from=build /home/gradle/src/build/libs/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-jar","/app/app.jar"]
