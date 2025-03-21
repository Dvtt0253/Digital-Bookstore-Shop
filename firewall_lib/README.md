## Flask_Firewall

A flask based Firewall that has a purpose of protecting flask web-apps from common attacks such as DDOS attacks(Denial Of Service Attacks), Automated Brute forcing attacks, SQL and XSS injection attacks , and CSRF attacks(Cross Site Request Foregery Attacks).

## Description
- Rate Limiting to protect against Denial of Service attacks
- Failed Login rate limiting to protect against brute force attacks
- Input sanitization and input checking to dilute input and check input for common malicious payloads
- CSRF token generation and CSRF token validation to protect against CSRF attacks
- IP whitelisting and blacklisting


## Installation 
1. Download the firewall_lib directory
2. Download the required packages listed in the requirements.txt file


## Usage
1. Add the firewall_lib directory to your prefered flask application directory
2. To import the firewall, use the following import: "from firewall_lib.flask_firewall import Firewall"
3. Initialize the Firewall class to a variable and pass in the required parameters (max_requests, time_window(in seconds)). ex. 'firewall_variable = Firewall(100, 60)'
4. Access functionality of the Firewall class through your created firewall variable. ex. 'firewall_variable.rate_limiter() or firewall_variable.login_limiter(3, 60)'

## Functions in the Firewall Class

1. rate_limiter() -- sets a limit of max_requests every time_window.
2. login_limiter(max_requests, time_window) -- sets a limit of login attempts of max_requests every time_window
3. santitize_input(user_input) -- takes input and santitizes and filters out HTML and Javascript characters and inserts
4. identify_payloads(user_iput) -- takes input and searches for any common SQL and XSS Payloads. If detected, it permanently blacklists the IP that has attempted entering the malicious payload.
5. block_access() -- checks if the current IP is present in the Permanent or Temporary blacklist. If so, blocks the IP from accessing the website.
6. start_TempBlacklist_removal() -- removes temporarily blacklisted IPs every 30 minutes. 
7. is_blacklisted(ip_address) -- returns true if given IP is blacklisted.
8. startperiodic_check() -- tracks the number of times a user has been temporarily blacklisted
9. temp_blacklist_threshold() -- permanently blacklists users who have been temporarily blacklisted for violations three or more times. 
10. remove_from_PermBlacklist(ip_address) -- removes the given IP address from the permanent blacklist
11. manual_temp_removal(ip_adress) -- removes the given IP from the temporary blacklist
12. add_to_whitelist(ip_address) -- adds the given IP to the whitelist
13. remove_from_whitelist(ip_address) -- removes the given IP from the whitelist
14. is_whitelisted(ip_address) -- returns true if the given IP is whitelisted
15. generate_CSRF_Token(length) -- returns a CSRF token of the given length 
16. validate_CSRF(original_CSRF, entered_CSRF) -- checks and validates if the given CSRF token matches the original generated CSRF token.












