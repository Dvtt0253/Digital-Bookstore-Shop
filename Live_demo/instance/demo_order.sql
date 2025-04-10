CREATE TABLE demo_order (
        id INTEGER NOT NULL, 
        user_id INTEGER NOT NULL, 
        item_title TEXT NOT NULL, 
        item_author TEXT NOT NULL, 
        total_price NUMERIC NOT NULL, 
        item_id INTEGER NOT NULL, 
        book_image VARCHAR(250) NOT NULL, 
        book_file VARCHAR(300) NOT NULL, 
        PRIMARY KEY (id)
);