-- Add migration script here
ALTER TABLE worlds ADD COLUMN version INTEGER NOT NULL;
