ALTER TABLE worlds DROP COLUMN difficulty;

ALTER TABLE world_versions ADD COLUMN difficulty TEXT NOT NULL CHECK (difficulty IN ('peaceful', 'easy', 'normal', 'hard'));