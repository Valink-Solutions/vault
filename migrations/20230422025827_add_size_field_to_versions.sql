-- Add migration script here
ALTER TABLE world_versions ADD COLUMN size BIGINT NOT NULL;
