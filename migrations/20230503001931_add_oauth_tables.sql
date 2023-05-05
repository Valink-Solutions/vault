-- Add migration script here
CREATE TABLE oauth_clients (
    client_id uuid PRIMARY KEY,
    client_secret VARCHAR(80) NOT NULL,
    name VARCHAR(30) NOT NULL DEFAULT 'Third-Party App',
    redirect_uri VARCHAR(2000),
    grant_types VARCHAR(80),
    scope VARCHAR(4000),
    user_id uuid REFERENCES users(id)
);

CREATE TABLE oauth_authorization_codes (
    code VARCHAR(256) PRIMARY KEY,
    client_id uuid NOT NULL,
    redirect_uri VARCHAR(2000),
    user_id uuid NOT NULL,
    expires TIMESTAMP NOT NULL,
    scope VARCHAR(4000),
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE oauth_access_tokens (
    access_token uuid PRIMARY KEY,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    expires TIMESTAMP NOT NULL,
    scope VARCHAR(4000),
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE oauth_refresh_tokens (
    refresh_token VARCHAR(64) PRIMARY KEY,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    expires TIMESTAMP NOT NULL,
    scope VARCHAR(4000),
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

DROP TABLE IF EXISTS sessions;
