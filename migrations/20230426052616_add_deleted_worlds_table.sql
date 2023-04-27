-- Add migration script here
CREATE TABLE deleted_worlds (
    id SERIAL PRIMARY KEY,
    world_id UUID NOT NULL,
    user_id UUID NOT NULL
);