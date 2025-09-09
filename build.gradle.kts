import org.openapitools.generator.gradle.plugin.tasks.GenerateTask

plugins {
	java
	id("org.springframework.boot") version "3.5.5"
	id("io.spring.dependency-management") version "1.1.7"
    id("org.openapi.generator") version "7.7.0"
}

group = "io.assignment"
version = "0.0.1-SNAPSHOT"
description = "An assignment project for Spring Boot"

java {
	toolchain {
		languageVersion = JavaLanguageVersion.of(21)
	}
}

repositories {
	mavenCentral()
}

// Removed dependencyManagement for Testcontainers BOM

dependencies {
	implementation("org.springframework.boot:spring-boot-starter-data-jpa")
	implementation("org.springframework.boot:spring-boot-starter-oauth2-client")
	implementation("org.springframework.boot:spring-boot-starter-security")
	implementation("org.springframework.boot:spring-boot-starter-validation")
	implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springdoc:springdoc-openapi-starter-webmvc-ui:2.8.13")
	implementation("org.flywaydb:flyway-core")
	implementation("org.flywaydb:flyway-database-postgresql")

    // Lombok 설정 수정
    compileOnly("org.projectlombok:lombok")
    annotationProcessor("org.projectlombok:lombok")
    testCompileOnly("org.projectlombok:lombok")
    testAnnotationProcessor("org.projectlombok:lombok")

	runtimeOnly("org.postgresql:postgresql")
	testImplementation("org.springframework.boot:spring-boot-starter-test")
	testImplementation("org.springframework.security:spring-security-test")
	testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    // Testcontainers for PostgreSQL, JUnit Jupiter, and Redis with explicit versions
    testImplementation("org.testcontainers:junit-jupiter:1.19.8")
    testImplementation("org.testcontainers:postgresql:1.19.8")
    

	// JWT 라이브러리
	implementation("io.jsonwebtoken:jjwt-api:0.12.5")
	runtimeOnly("io.jsonwebtoken:jjwt-impl:0.12.5")
	runtimeOnly("io.jsonwebtoken:jjwt-jackson:0.12.5")

	// Redis
	implementation("org.springframework.boot:spring-boot-starter-data-redis")

	// TOTP (MFA) - java-otp & zxing
	implementation("com.eatthepath:java-otp:0.4.0")
	implementation("com.google.zxing:core:3.5.3")
	implementation("com.google.zxing:javase:3.5.3")
	implementation("commons-codec:commons-codec:1.17.0")

    // OpenAPI Generator가 사용하는 의존성 추가
    implementation("org.openapitools:jackson-databind-nullable:0.2.6")
}

tasks.withType<Test> {
	useJUnitPlatform()
}

val openApiOut = layout.buildDirectory.dir("generated")

tasks.named<GenerateTask>("openApiGenerate") {
    generatorName.set("spring")
    inputSpec.set("$rootDir/openapi.yaml")
    outputDir.set(layout.buildDirectory.dir("generated").get().asFile.absolutePath)
    apiPackage.set("io.assignment.auth.api")
    modelPackage.set("io.assignment.auth.dto")
    invokerPackage.set("io.assignment.auth")
    configOptions.set(
        mapOf(
            "useSpringBoot3" to "true",
            "useJakartaEe" to "true",
            "useTags" to "true",
            "dateLibrary" to "java8",
            "interfaceOnly" to "true",
            "useTags" to "true"
        )
    )
}

sourceSets {
    named("main") {
        java.srcDir(openApiOut.map { it.dir("src/main/java") })
    }
}

tasks.named("compileJava") {
    dependsOn("openApiGenerate")
}

tasks.named<Delete>("clean") {
    delete(openApiOut)
}

tasks.named("processResources") {
    dependsOn("openApiGenerate")
}