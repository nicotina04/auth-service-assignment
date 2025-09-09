package io.assignment.auth;

import io.assignment.auth.domain.User;
import io.assignment.auth.domain.UserStatus;
import io.assignment.auth.repository.UserRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.boot.test.mock.mockito.MockBean;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class AuthServiceApiAssignmentApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserRepository userRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private ObjectMapper objectMapper;

	private RedisTemplate<String, String> redisTemplate;

	@Container
	static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>(DockerImageName.parse("postgres:16"))
			.withInitScript("test-schema.sql"); // Changed init script

	@DynamicPropertySource
	static void configureProperties(DynamicPropertyRegistry registry) {
		registry.add("spring.datasource.url", postgres::getJdbcUrl);
		registry.add("spring.datasource.username", postgres::getUsername);
		registry.add("spring.datasource.password", postgres::getPassword);
		registry.add("spring.jpa.hibernate.ddl-auto", () -> "none");

		registry.add("spring.flyway.enabled", () -> "false"); // Explicitly disable Flyway

		registry.add("spring.security.oauth2.client.registration.google.client-id", () -> "test-client-id");
		registry.add("spring.security.oauth2.client.registration.google.client-secret", () -> "test-client-secret");
	}

	@Test
	void contextLoads() {
	}

	@Test
	@DisplayName("JWKS 엔드포인트는 인증 없이 공개적으로 접근 가능하다")
	void jwksEndpointIsPubliclyAccessible() throws Exception {
		mockMvc.perform(get("/.well-known/jwks.json"))
				.andExpect(status().isOk())
				.andExpect(content().contentType(MediaType.APPLICATION_JSON))
				.andExpect(jsonPath("$.keys").isArray());
	}

	@Test
	@DisplayName("유효한 자격 증명으로 로그인 시 성공한다")
	void loginWithValidCredentialsSucceeds() throws Exception {
		String email = "test@example.com";
		String password = "password123";
		User user = new User();
		user.setEmail(email);
		user.setPasswordHash(passwordEncoder.encode(password));
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		String loginRequestJson = """
				{
					"email": "%s",
					"password": "%s"
				}
				""".formatted(email, password);

		mockMvc.perform(post("/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(loginRequestJson))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.accessToken").exists())
				.andExpect(jsonPath("$.refreshToken").exists());
	}

	@Test
	@DisplayName("users 테이블이 데이터베이스에 존재한다")
	void usersTableExists() {
		Integer count = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM users", Integer.class);
		assertTrue(count >= 0, "users 테이블이 존재하고 쿼리할 수 있어야 합니다.");
	}

	@Test
	@DisplayName("잘못된 비밀번호로 로그인 시 실패한다")
	void loginWithInvalidPasswordFails() throws Exception {
		// given
		String email = "test-invalid-pass@example.com";
		String correctPassword = "password123";
		String wrongPassword = "wrongpassword";
		User user = new User();
		user.setEmail(email);
		user.setPasswordHash(passwordEncoder.encode(correctPassword));
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		String loginRequestJson = """
                {
                    "email": "%s",
                    "password": "%s"
                }
                """.formatted(email, wrongPassword);

		// when & then
		mockMvc.perform(post("/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(loginRequestJson))
				.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("존재하지 않는 이메일로 로그인 시 실패한다")
	void loginWithNonExistentUserFails() throws Exception {
		// given
		String nonExistentEmail = "nouser@example.com";
		String password = "password123";
		String loginRequestJson = """
                {
                    "email": "%s",
                    "password": "%s"
                }
                """.formatted(nonExistentEmail, password);

		// when & then
		mockMvc.perform(post("/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(loginRequestJson))
				.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("잠긴 계정으로 로그인 시 실패한다")
	void loginWithLockedUserFails() throws Exception {
		// given
		String email = "locked@example.com";
		String password = "password123";
		User user = new User();
		user.setEmail(email);
		user.setPasswordHash(passwordEncoder.encode(password));
		user.setStatus(UserStatus.LOCKED);
		userRepository.save(user);

		String loginRequestJson = """
                {
                    "email": "%s",
                    "password": "%s"
                }
                """.formatted(email, password);

		// when & then
		mockMvc.perform(post("/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(loginRequestJson))
				.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("올바른 엑세스 토큰으로 /me에 요청하면 200을 반환한다")
	void meEndpointReturnsUserInfoWithValidToken() throws Exception {
		String email = "me-user@example.com";
		String password = "password123";
		User user = new User();
		user.setEmail(email);
		user.setPasswordHash(passwordEncoder.encode(password));
		user.setStatus(UserStatus.ACTIVE);
		userRepository.save(user);

		String loginRequestJson = """
				{
					"email": "%s",
					"password": "%s"
				}
				""".formatted(email, password);

		var loginResult = mockMvc.perform(post("/auth/login")
				.contentType(MediaType.APPLICATION_JSON)
				.content(loginRequestJson))
			.andExpect(status().isOk())
			.andReturn();

		String body = loginResult.getResponse().getContentAsString();
		JsonNode root = objectMapper.readTree(body);
		String accessToken = root.get("accessToken").asText();

		mockMvc.perform(get("/me").header("Authorization", "Bearer " + accessToken))
			.andExpect(status().isOk())
			.andExpect(content().contentType(MediaType.APPLICATION_JSON))
			.andExpect(jsonPath("$.email").value(email))
			.andExpect(jsonPath("$.id").exists())
			.andExpect(jsonPath("$.status").value("ACTIVE"))
			.andExpect(jsonPath("$.roles").isArray());
	}

}
