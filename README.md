# RBAC API Repository

This repository contains the code and resources for the Role-Based Access Control (RBAC) API for OTA.OTA stands for "Over-the-Air". It also includes a Postman collection to facilitate testing the API endpoints.

---

## Features
- User creation with role and also permission assignment little code change
- Role-based permissions (`create_user`, `upload_apk`, `release_product`)
- Login and for First time login OTP-based authentication
- Comprehensive user activity logging
- User reset password also admin can change user role and password
- Support for user updates and soft deletion
- Integrated with Django REST Framework (DRF)

---

## Prerequisites
- Python 3.10.6
- Django 4.1.3
- Django REST Framework
- Postman (for API testing)

---

## Installation

1. Clone the repository:
    ```bash
    git clone <repository_url>
    cd <repository_name>
    ``` 
2.0 (optional) set Docker image and run the container

2. Set up a virtual environment:
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3. Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Apply migrations:
    ```bash
    python manage.py makemigrations
    python manage.py migrate
    ```

5. Create a superuser:
    ```"django Custom migration set all permission assign and role creation with superuser 
    ```

6. Start the development server:
    ```bash
    python manage.py runserver
    ```

---

## Postman Collection

### Included Collection
The repository includes a Postman collection for testing the API. You can find it in the `postman/` folder:
- [RBAC_.postman_collection](postman/RBAC_.postman_collection)

### Importing the Collection
1. Download the collection file from the `postman/` folder.
2. Open Postman and click **Import** in the top left.
3. Drag and drop the `.postman_collection` file or browse to upload it.

### Using the Collection
- The collection includes all necessary endpoints for user creation, authentication, and role management.
- Update the variable in Postman to point to your running server, e.g., `username`,`password`.

---

## API Overview

### Key Endpoints
1. **User Management**
    - `POST /users/`: Create a new user with roles and permissions.
    - `GET /users/`: List users with their roles and permissions.
    - `PUT /users/`: Update a user's details.
    - `DELETE /users/`: Soft-delete a user.

2. **Authentication**
    - `POST /auth/login/`: User login with OTP verification.
    - `POST /auth/logout/`: User logout.

3. **Roles and Permissions**
    - `GET /user_roles/`: List all roles.
    - `GET /permissions/`: List permissions for a role.

### Example Request: User Creation
```json
POST /users/
{
"email":"dev1@inst.com",
"first_name":"developer",
"last_name":"django",
"password":"Testabc123#",
"role":3
}
