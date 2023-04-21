-- Create users table
CREATE TABLE users (
    id uuid PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) UNIQUE,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('admin', 'user')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX users_email_idx ON users (email);

-- Create worlds table
CREATE TABLE worlds (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL,
    name VARCHAR(255) NOT NULL,
    seed BIGINT NOT NULL,
    difficulty TEXT NOT NULL CHECK (difficulty IN ('peaceful', 'easy', 'normal', 'hard')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create world_versions table
CREATE TABLE world_versions (
    id uuid PRIMARY KEY,
    world_id uuid NOT NULL,
    version_number INT NOT NULL,
    backup_path VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    game_mode TEXT NOT NULL CHECK (game_mode IN ('survival', 'creative', 'adventure', 'spectator')),
    allow_cheats BOOLEAN NOT NULL,
    difficulty_locked BOOLEAN NOT NULL,
    spawn_x INT NOT NULL,
    spawn_y INT NOT NULL,
    spawn_z INT NOT NULL,
    time BIGINT NOT NULL,
    weather TEXT NOT NULL CHECK (weather IN ('clear', 'rain', 'thunder')),
    hardcore BOOLEAN NOT NULL,
    command_blocks_enabled BOOLEAN NOT NULL,
    command_block_output BOOLEAN NOT NULL,
    do_daylight_cycle BOOLEAN NOT NULL,
    do_mob_spawning BOOLEAN NOT NULL,
    do_weather_cycle BOOLEAN NOT NULL,
    keep_inventory BOOLEAN NOT NULL,
    max_players INT NOT NULL,
    view_distance INT NOT NULL,
    level_name VARCHAR(255) NOT NULL,
    resource_pack VARCHAR(255),
    resource_pack_sha1 VARCHAR(255),
    FOREIGN KEY (world_id) REFERENCES worlds(id) ON DELETE CASCADE
);
