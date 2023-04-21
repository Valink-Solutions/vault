-- Add migration script here
CREATE TABLE sessions (
    token_uuid uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
