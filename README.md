# Web Forum Project

### About the Project
This project is a simple web forum built in Go, using SQLite for data storage. It allows registered users to create posts, comment on them, and engage with others through likes and dislikes. Posts can be categorized and filtered to improve usability. The forum ensures a secure, structured, and user-friendly experience with session-based authentication and robust error handling.


## Features
.User Communication: Create posts and comments.
.Categorization: Associate posts with one or more categories.
.Authentication: Secure user registration and login with session management.
.Likes and Dislikes: Users can interact with posts and comments.
.Filtering: Filter posts by categories, user-created posts, or liked posts.
.Error Handling: Includes HTTP status and technical error handling.

## Technologies Used
Go: Backend development and server logic.
SQLite: Lightweight database for local data storage.
HTML: Frontend design and user interface.
Docker: Containerization for deployment and compatibility.
bcrypt: For password encryption (Bonus task).
UUID: Unique identifier for user sessions (Bonus task).

## Authentication
User Registration:
Users must provide a unique email, username, and password.
The password can be encrypted for additional security (Bonus task).
Login:
Validates credentials and creates a session stored in a cookie.
Sessions have an expiration date (configurable).
Session Management:
Each user can only have one active session.

## Communication Features
Posts:
Registered users can create posts with one or more categories.
Posts are visible to all users, including non-registered ones.
Comments:
Registered users can comment on any post.
Comments are also visible to all users.


## Likes and Dislikes
Registered users can like or dislike posts and comments.
The count of likes and dislikes is visible to all users.


## Filter Mechanism
Users can filter posts by:

#### Categories: Subforums for specific topics.
User-Created Posts: View posts created by the logged-in user.
Liked Posts: View posts liked by the logged-in user.

#### Error Handling
Website Errors: Return appropriate HTTP status codes (e.g., 404 for not found).
Technical Errors: Handle database and server errors gracefully.



https://excalidraw.com/#room=78ee7d099278a6b0809a,0IoUBRQD8-AWrZIrgc8EgQ

