CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    ldap_username VARCHAR(100) NOT NULL,
    mac_address VARCHAR(32),
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    UNIQUE KEY unique_ldap_username (ldap_username)
);

CREATE TABLE sessions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    start_time DATETIME NOT NULL,
    end_time DATETIME,
    source VARCHAR(16) NOT NULL DEFAULT 'manual',
    note TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id),
    INDEX idx_sessions_user_start (user_id, start_time)
);
