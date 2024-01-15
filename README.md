#Game-App
Here at the Game-App repository, welcome! For instructional reasons, this project tries to illustrate secure coding methods and weaknesses.

## Vulnerabilities in Insecure Versions

1. **Flaw in SQL Injection:**
   Because the insecure version builds queries with user inputs without validation, it permits SQL injection. The database may become uninvitedly accessible as a result.

**Cross-Site Scripting (XSS) Vulnerabilities:** - Reflective XSS: User inputs in routes are potentially script-injected since they are not properly sanitized.
   - Stored and DOM-Based XSS: Security threats arise from situations where malicious scripts may be placed in the DOM or saved data.

3. **Exposure to Sensitive Data:**
   Routes lack adequate authentication, and passwords are kept in plain text in the database, increasing the danger of unwanted access to private data.

## Security Measures for the Secure Version

1. **Cross-Site Request Forgery (CSRF) Token:** Tokens for secure form submissions were generated and validated using the csurf middleware to implement CSRF protection.


2. **Correct Session Management:** To ensure distinct session tokens, secure cookies, and proper handling of session timeouts, the express-session middleware was employed for secure session management.

3. **Use of Security Headers:** Strict Transport Security and Content Security Policy were two features that were implemented using security headers using the Helmet middleware to improve application security.

4. **Adequate Logging and Monitoring:** The Morgan middleware was used to enable the logging of important events, giving monitoring and incident response teams a thorough audit trail.

## Git Project Problems & Issues

### Problems with Git

- **Problem #1: Vulnerability for SQL Injection**
  - Description: Fix the user authentication SQL injection vulnerability.
  The assignees are @developer1. Tags: security, bug

**Problem #2: XSS Exposures**
  - Description: Prevent XSS vulnerabilities by using appropriate input sanitization.
  The assignees are @developer2. Labels: protection, improvement

### Project Boards for Git

#### To-Do List:
Columns: Completed, In Progress, Backlog, and To-Do
Organize duties related to vulnerabilities and features.

#### Security Board:
Columns: Testing, Documentation, Security Measures, Vulnerabilities
Monitor the advancement of resolving security concerns, putting procedures in place, conducting tests, and recording modifications.
