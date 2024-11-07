CREATE TABLE Users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    password TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- CREATE TABLE PostCategories (
--     category_id INTEGER PRIMARY KEY AUTOINCREMENT,
--     post_id INTEGER,
--     category_name TEXT  NOT NULL,
--     FOREIGN KEY (post_id) REFERENCES Posts(post_id)
-- );



CREATE TABLE Posts (
    post_id INTEGER PRIMARY KEY AUTOINCREMENT, 
    user_id INTEGER,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    categories TEXT  NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
);

CREATE TABLE Reactions (
    reaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    user_id INTEGER,
    reaction_type TEXT CHECK(reaction_type IN ('LIKE', 'DISLIKE')), /* HNA KHASSNI NZID WN9SS*/
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES Posts(post_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    UNIQUE(post_id, user_id)
);

CREATE TABLE Comment_Reaction (
    com_reaction_id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    user_id INTEGER,
    reaction_type TEXT CHECK(reaction_type IN ('LIKE', 'DISLIKE')), /* HNA KHASSNI NZID WN9SS*/
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES Posts(post_id),
    FOREIGN KEY (user_id) REFERENCES Users(user_id),
    UNIQUE(post_id, user_id)
);


CREATE TABLE Comment (
    comment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    username TEXT,
    comment_content TEXT NOT NULL,
    comment_date DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES Posts(post_id)
);


