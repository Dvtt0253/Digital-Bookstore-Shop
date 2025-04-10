CREATE TABLE user (
        id INTEGER NOT NULL, 
        first_name TEXT NOT NULL, 
        last_name TEXT NOT NULL, 
        email VARCHAR(200) NOT NULL, 
        hashed_password VARCHAR(300) NOT NULL, 
        is_verified BOOLEAN NOT NULL, 
        user_ip VARCHAR(100), 
        user_agent VARCHAR(250), 
        join_date DATETIME NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (email)
);