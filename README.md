# Secured CRS

A Java 21 and Spring Boot 4.0.9 course registration API. Catalog, enrollment, and account records are kept in memory. Changes to courses and enrollments reset on restart.

## Build and test

Install JDK 21 and Maven 3.9. From the project directory, run:

```text
mvn clean verify
```

The tests exercise real signed tokens, signature tampering, expired tokens, stateless requests, BCrypt storage, CORS, and the authorization matrix. Direct service calls also verify that Spring Method Security enforces access independently of MVC. The included GitHub Actions workflow runs the same Maven gate on pushes and pull requests.

## Run locally

Generate a distinct password hash for each account. Run the following command four times in an interactive terminal. It prompts for the password without echoing it.

```text
java -jar target/secured-crs-1.0.0.jar --hash-password
```

In PowerShell, paste each resulting hash inside single quotes so PowerShell preserves its dollar signs. Replace all placeholders before starting the application.

```powershell
$env:CRS_ACCOUNTS_ALICE_HASH = '<Alice BCrypt hash>'
$env:CRS_ACCOUNTS_BOB_HASH = '<Bob BCrypt hash>'
$env:CRS_ACCOUNTS_ADVISOR_HASH = '<Advisor BCrypt hash>'
$env:CRS_ACCOUNTS_REGISTRAR_HASH = '<Registrar BCrypt hash>'
$env:CRS_MOBILE_ORIGIN = 'http://localhost:8100'

java -jar target/secured-crs-1.0.0.jar
```

The API listens on `127.0.0.1:8080` by default. Set `CRS_MOBILE_ORIGIN` to the exact origin sent by your mobile client's browser or WebView, including the port when present. The CORS policy permits one origin and accepts the Authorization and Content-Type headers. Browser preflight is handled before bearer authentication.

JWTs expire after 15 minutes. The app generates a fresh signing key on startup by default, so a restart invalidates issued tokens. Set `CRS_JWT_SECRET` to a Base64-encoded random key of at least 32 bytes when instances need to share signing state.

## Endpoints

| Method and path | Access | JSON body |
| --- | --- | --- |
| POST `/api/auth/token` | Valid account credentials | `{"username":"alice","password":"<Alice password>"}` |
| GET `/api/courses` | Any authenticated account | |
| GET `/api/courses/{code}` | Any authenticated account | |
| POST `/api/courses` | REGISTRAR | `{"code":"CS301","title":"Algorithms"}` |
| GET `/api/students/{student}/enrollments` | Student themself, assigned advisor, or registrar | |
| POST `/api/students/{student}/enrollments` | Student themself, assigned advisor, or registrar | `{"courseCode":"CS201"}` |
| DELETE `/api/students/{student}/enrollments/{courseCode}` | Student themself, assigned advisor, or registrar | |

The token response contains `accessToken`, `tokenType`, and `expiresIn` in seconds. Send `Authorization: Bearer <accessToken>` on protected requests. Student identifiers are the canonical usernames `alice` and `bob`. The server-side `Caseload` component assigns `advisor` to Alice only. Initially Alice is enrolled in CS101 and Bob is enrolled in CS201.

## Quick Postman checks

1. Send `POST http://127.0.0.1:8080/api/auth/token` with the JSON credentials for Alice. Copy `accessToken` from the 200 response.
2. Select **Bearer Token** in Postman's Authorization tab on the requests below and paste the token.
3. Change tokens by repeating step 1 with `advisor` or `registrar` and that account's password.

| Account | Request | Expected |
| --- | --- | --- |
| None | GET `/api/courses` | 401 |
| Alice | GET `/api/students/alice/enrollments` | 200 |
| Alice | GET `/api/students/bob/enrollments` | 403 |
| Alice | POST `/api/courses` with the catalog JSON above | 403 |
| Advisor | GET `/api/students/alice/enrollments` | 200 |
| Advisor | GET `/api/students/bob/enrollments` | 403 |
| Registrar | POST `/api/courses` with the catalog JSON above | 201 |
| Registrar | GET `/api/students/bob/enrollments` | 200 |
