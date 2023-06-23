
### jwt-spring-security-example ( for Spring Boot Version 2.7.12)

This repository provides a comprehensive example of how to implement JWT (JSON Web Token) authentication and authorization in a Spring Security-based application. It showcases a secure and stateless authentication mechanism using JWT tokens, allowing for easy integration into various Spring Boot projects.


## Required files to create

```java
- config
  |- jwt
  |  |- JwtAuthenticationEntryPoint.java
  |  |- JwtRequestFilter.java
  |  |- JwtTokenProvider.java
  |
  |- security
  |  |- SecurityConfig.java
  |
  |- user
     |- User.java
     |- UserController.java
     |- UserLoginDto.java
     |- UserRepository.java
     |- UserService.java

```


## Step 1: JwtTokenProvider

- Create a new class called JwtTokenProvider in the config.jwt package.
- Implement methods to generate JWT tokens, validate tokens, and extract user details from tokens.


## Step 2: JwtAuthenticationEntryPoint

- Create a new class called JwtAuthenticationEntryPoint in the config.jwt package.
- Implement the logic to handle unauthorized access and return appropriate error responses.

## Step 3: JwtRequestFilter

- Create a new class called JwtRequestFilter in the config.jwt package.
- Implement the logic to intercept incoming requests, extract the JWT token, and validate it.



## Step 4: SecurityConfig

- Create a new class called SecurityConfig in the config.security package.
- Annotate the class with @EnableWebSecurity and extend WebSecurityConfigurerAdapter.
- Override the configure(HttpSecurity http) method to define the security configurations.
- Configure the JwtRequestFilter as a filter in the security chain.
- Define the authentication entry point and configure any other security rules or settings.


## Step 5: User

- Create a new class called User in the user package.
- Define the structure and attributes of the user entity.

## Step 6: UserRepository

- Create a new class called UserRepository in the user package.
- Implement the logic to perform CRUD operations for the User entity.

## Step 7: UserController

- Create a new class called UserController in the user package.
- Implement the REST API endpoints for user-related operations, such as registration, login, profile retrieval, etc.


## Step 8: UserService

- Create a new class called UserService in the user package.
- Implement the business logic for user-related operations, including authentication and user management.

## Dependencies

**Dependencies:** Spring Data JPA, Spring Security, Spring Web, Mysql Driver, jjwt 

