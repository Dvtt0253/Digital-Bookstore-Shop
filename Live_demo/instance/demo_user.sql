CREATE TABLE demo_user (
        id INTEGER NOT NULL, 
        first_name TEXT NOT NULL, 
        last_name TEXT NOT NULL, 
        email VARCHAR(200) NOT NULL, 
        hashed_password VARCHAR(300) NOT NULL, 
        join_date DATETIME NOT NULL, 
        PRIMARY KEY (id), 
        UNIQUE (email)
);