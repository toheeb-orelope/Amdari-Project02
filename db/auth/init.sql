-- auth-service schema. Passwords stored with MD5 (AV-05).

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(64) NOT NULL,
    email VARCHAR(128),
    role VARCHAR(32) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- MD5('admin123')  = 0192023a7bbd73250516f069df18b500
-- MD5('alice123')  = 8d7dd611a2c81e9dc1b3a6e6effc4845
-- MD5('bob123')    = 2ab96390c7dbe3439de74d0c9b0b1767
-- (real MD5s — interns can crack them with rockyou in seconds.)

INSERT INTO users (username, password_hash, email, role) VALUES
    ('admin', '0192023a7bbd73250516f069df18b500', 'admin@secureflow.local', 'admin'),
    ('alice', '8d7dd611a2c81e9dc1b3a6e6effc4845', 'alice@secureflow.local', 'user'),
    ('bob',   '2ab96390c7dbe3439de74d0c9b0b1767', 'bob@secureflow.local',   'user')
ON CONFLICT (username) DO NOTHING;
