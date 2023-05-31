-- Add migration script here
CREATE TABLE api_keys (
    key_id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    key_secret_hash VARCHAR(255) NOT NULL,
    name VARCHAR(30) NOT NULL,
    expires TIMESTAMP NOT NULL,
    scope VARCHAR(4000),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Add forgotten username index
CREATE INDEX users_username_idx ON users (username);
