# Spring Security JWT

Это приложение использует Spring Security и JWT (JSON Web Token) для управления аутентификацией и авторизацией пользователей. Оно предоставляет возможности для регистрации, аутентификации пользователей, а также примеры использования различных уровней доступа. также поддерживает протокол https и реализует механизм блокировки аккаунтов после нескольких неудачных попыток входа.

## Основные компоненты

### Контроллеры

#### `AccountController`

Этот контроллер обрабатывает запросы, связанные с аутентификацией пользователей.

- **Регистрация пользователя** (`POST /auth/sign-up`): 
  Принимает запросы на регистрацию пользователей. Запросы валидируются на основе аннотаций `@NotBlank`, `@Size` и `@Email`, обеспечивая корректность имени пользователя, электронной почты и пароля. При успешной регистрации пользователю выдается JWT.

- **Авторизация пользователя** (`POST /auth/sign-in`):
  Обрабатывает запросы на аутентификацию пользователей. Запросы валидируются на основе аннотаций `@NotBlank` и `@Size`, проверяя корректность имени пользователя и пароля. При успешной аутентификации пользователю возвращается JWT.

#### `ExampleController`

Этот контроллер демонстрирует различные уровни доступа.

- **Пример доступа для всех авторизованных пользователей** (`GET /example`):
  Доступен только авторизованным пользователям. Возвращает строку "Hello, world!".

- **Пример доступа для администраторов** (`GET /example/admin`):
  Доступен только пользователям с ролью ADMIN. Возвращает строку "Hello, admin!".

- **Получение роли ADMIN (для демонстрации)** (`GET /example/get-admin`):
  Предназначен для демонстрации и позволяет текущему пользователю получить роль ADMIN.

### DTO

- **SignInRequest**:
  Запрос для аутентификации, содержащий имя пользователя и пароль. Валидируется на основе аннотаций `@NotBlank` и `@Size`.

- **SignUpRequest**:
  Запрос для регистрации, содержащий имя пользователя, адрес электронной почты и пароль. Валидируется на основе аннотаций `@NotBlank`, `@Size` и `@Email`.

### Модели

- **Role**: Перечисление ролей пользователей: `ROLE_USER`, `ROLE_ADMIN`, `ROLE_MODERATOR`, `ROLE_SUPER_ADMIN`.

- **User**: Сущность пользователя с полями: `id`, `username`, `password`, `email`, и `role`. Реализует интерфейс `UserDetails` для интеграции со Spring Security.

### Репозитории

- **UserRepository**: Репозиторий для сущности `User`, предоставляющий методы для поиска пользователей по имени и проверки уникальности имени и электронной почты.

### Конфигурация безопасности

- **SecurityConfig**: Конфигурация безопасности для настройки фильтрации запросов, авторизации и аутентификации. Использует JWT для безсессионной аутентификации и настроен для обработки различных уровней доступа.

- **JwtAuthenticationFilter**: Фильтр для проверки JWT в запросах и установки аутентификации в контексте безопасности.

- **JwtUtil**: Утилитный класс для генерации и проверки JWT. Использует секретный ключ для подписи токенов и проверки их подлинности.

### Сервисы

- **AuthenticationService**: Сервис для регистрации и аутентификации пользователей. Генерирует JWT для успешных операций.

- **UserDetailsServiceImpl**: Реализация `UserDetailsService` для загрузки пользователей по имени пользователя.

- **UserService**: Сервис для управления пользователями, включая создание, получение текущего пользователя и демонстрационное повышение прав до ADMIN.

## Примеры запросов (Postman)

- **Регистрация пользователя**:

  - Метод: POST
  - URL: `http://localhost:8443/auth/sign-up`
  - Тело запроса (JSON):
    ```json
    {
      "username": "user",
      "email": "user@example.com",
      "password": "password"
    }
    ```
  - Заголовки:
    - Content-Type: `application/json`

- **Авторизация пользователя**:

  - Метод: POST
  - URL: `http://localhost:8443/auth/sign-in`
  - Тело запроса (JSON):
    ```json
    {
      "username": "user",
      "password": "password"
    }
    ```
  - Заголовки:
    - Content-Type: `application/json`

- **Получение примера доступа для всех авторизованных пользователей**:

  - Метод: GET
  - URL: `https://localhost:8443/example`
  - Заголовки:
    - Authorization: `Bearer <token>`

- **Получение примера доступа для администраторов**:

  - Метод: GET
  - URL: `https://localhost:8443/example/admin`
  - Заголовки:
    - Authorization: `Bearer <token>`

- **Получение примера доступа для модераторов**:

  - Метод: GET
  - URL: `https://localhost:8443/example/moderator`
  - Заголовки:
    - Authorization: `Bearer <token>`

- **Изменение роли текущего пользователя**:

  - Метод: GET
  - URL: `https://localhost:8443/example/get-ROLE_USER`
  - Заголовки:
    - Authorization: `Bearer <token>`

  - URL: `https://localhost:8443/example/get-ROLE_ADMIN`
  - Заголовки:
    - Authorization: `Bearer <token>`

