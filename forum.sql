CREATE TABLE Users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE PostCategories (
    category_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    category_name TEXT UNIQUE NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE Posts (
    post_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    category_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    FOREIGN KEY (category_id) REFERENCES PostCategories(category_id)
);

CREATE TABLE Reactions (
    reaction_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    post_id INTEGER,
    user_id INTEGER,
    reaction_type TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES Posts(post_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id)
);

-- DROP TABLE Users;
-- DROP TABLE PostCategories;DROP TABLE Posts;DROP TABLE Reactions;

