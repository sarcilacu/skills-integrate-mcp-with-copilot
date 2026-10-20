# Mergington High School Activities API

A super simple FastAPI application that allows students to view and sign up for extracurricular activities.

## Features

- View all available extracurricular activities
- Students can sign themselves up without logging in
- Teachers can unregister students after logging in
- Teacher login backed by locally configured credentials
- Students and visitors can view activities and participant lists without logging in

## Getting Started

1. Install the dependencies:

   ```
   pip install -r requirements.txt
   ```

2. Create `src/teachers.json` using the example file as a template. Generate a salted password hash in a terminal without echoing the password:

   ```sh
   cd src
   cp teachers.example.json teachers.json
   python -c 'import getpass, hashlib, secrets; salt = secrets.token_hex(16); password = getpass.getpass(); print("salt:", salt); print("password_hash:", hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 600000).hex())'
   ```

   Add a teacher record containing the chosen username and the generated `salt` and `password_hash` to `teachers.json`. That file is ignored by Git and should not be committed.

3. Set a session signing key and run the application:

   ```
   export SESSION_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
   uvicorn app:app --reload
   ```

   For HTTPS deployments, also set `COOKIE_SECURE=true`.

4. Open your browser and go to:
   - API documentation: http://localhost:8000/docs
   - Alternative documentation: http://localhost:8000/redoc

## API Endpoints

| Method | Endpoint                                                          | Description                                                         |
| ------ | ----------------------------------------------------------------- | ------------------------------------------------------------------- |
| GET    | `/activities`                                                     | Get all activities with their details and current participant count |
| GET    | `/auth/me`                                                         | Check the current teacher session                                  |
| POST   | `/auth/login`                                                      | Sign in a teacher using JSON username and password                 |
| POST   | `/auth/logout`                                                     | Sign out the current teacher                                       |
| POST   | `/activities/{activity_name}/signup?email=student@mergington.edu` | Sign up for an activity                                             |
| DELETE | `/activities/{activity_name}/unregister?email=student@mergington.edu` | Unregister a student from an activity                           |

Signup is public so students can register themselves without an account. Unregister requires a teacher session, enforced by the API regardless of the client; only logged-in teachers see removal controls in the browser.

## Data Model

The application uses a simple data model with meaningful identifiers:

1. **Activities** - Uses activity name as identifier:

   - Description
   - Schedule
   - Maximum number of participants allowed
   - List of student emails who are signed up

2. **Students** - Uses email as identifier:
   - Name
   - Grade level

All data is stored in memory, which means data will be reset when the server restarts.
