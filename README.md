# Digital-Bookstore-Shop-ShelfSpace

A demo e-commerce website, built using Flask and SQLAlchemy, that was designed to sell digital books. It handles foundational features such as a user shopping cart, user authentication, session management and data handling, and integrated web security measures such as, IP tracking, csrf token integration into all submitted forms, and a custom-built firewall which handles rate limiting, and protections against brute force attacks and payload injection attacks.



## Usage and Installation

### To install and run the web application:

1. [Click Here](https://github.com/Dvtt0253/Digital-Bookstore-Shop/archive/refs/heads/main.zip) to download the repository's ZIP file
2. Once installed, navigate to your terminal and open the folder. Ex - `cd Digital-Bookstore-Shop(replace with exact name of the directory)`
3. Once inside of the project's folder, install the required libraries from the requirements.txt file using the command: `pip install -r requirements.txt`
4. Before running the app, ensure that port 5003 is cleared with `lsof -i :5003` and if occupied clear the ports with `kill -9 <PID(enter the PID number here)>`
5. Run the app with the following command: `python newstore.py or python3 newstore.py`

#### Click the link below to view the Demo videos for the digital bookstore - ShelfSpace ####
[Click here to view the demo videos](https://drive.google.com/drive/folders/1tzoSzPOW6Vlq4D9VJZwics7ACSoyuMjc?usp=drive_link)




## Features
- **User authentication and password hashing**
- **IP Tracking**: Tracks and stores users' IPs to protect against unauthorized logins
- **Shopping cart functionality**: Allows users to manage their shopping carts
- **CSRF protections**: Integrates CSRF tokens into all submitted forms to protect against CSRF attacks
- **Custom-built firewall**: protects against brute force attacks with failed login rate limiting, malicious payload injections through verifying and sanitizing user input, and DDOS attacks(denial of service attacks) through rate limiting. Additionally, it handles IP blacklisting and whitelisting.
- **Password validation**: validates users' passwords to ensure that all passwords are secure and unique


## Technologies used

- **Flask**: Used for managing HTTP requests and responses for the web application
- **SQLAlchemy**: Used for managing database entries and database queries 
- **Argon2**: Used for hashing users' passwords to ensure secure password storage within the database.
- **HTML and Javascript**: Used for creating the users' interface and ensuring user interactivity.




## Copyright

Copyright (c) 2025 Joie Harvey. All rights reserved.



  
  


  
