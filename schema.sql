CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    ldap_username VARCHAR(100) NOT NULL,
    mac_address VARCHAR(32),
    UNIQUE KEY unique_ldap_username (ldap_username)
);

CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    note TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
