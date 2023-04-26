-- Create users table
CREATE TABLE users (
    id uuid PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX users_email_idx ON users (email);

-- Create sessions table
CREATE TABLE sessions (
    token_uuid uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Create worlds table
CREATE TABLE worlds (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    name VARCHAR(255) NOT NULL,
    current_version INTEGER NOT NULL,
    seed BIGINT NOT NULL,
    edition TEXT NOT NULL CHECK (edition IN ('java', 'bedrock')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create world_versions table
CREATE TABLE world_versions (
    id uuid PRIMARY KEY,
    world_id uuid NOT NULL,
    version INT NOT NULL,
    backup_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    game_mode TEXT NOT NULL CHECK (game_mode IN ('survival', 'creative', 'adventure', 'spectator')),
    difficulty TEXT NOT NULL CHECK (difficulty IN ('peaceful', 'easy', 'normal', 'hard')),
    allow_cheats BOOLEAN NOT NULL,
    difficulty_locked BOOLEAN NOT NULL,
    spawn_x INT NOT NULL,
    spawn_y INT NOT NULL,
    spawn_z INT NOT NULL,
    time BIGINT NOT NULL,
    weather TEXT NOT NULL CHECK (weather IN ('clear', 'rain', 'thunder')),
    hardcore BOOLEAN NOT NULL,
    do_daylight_cycle BOOLEAN NOT NULL,
    do_mob_spawning BOOLEAN NOT NULL,
    do_weather_cycle BOOLEAN NOT NULL,
    keep_inventory BOOLEAN NOT NULL,
    size BIGINT NOT NULL,
    level_name VARCHAR(255) NOT NULL,
    additional_data JSON,
    FOREIGN KEY (world_id) REFERENCES worlds(id) ON DELETE CASCADE
);
