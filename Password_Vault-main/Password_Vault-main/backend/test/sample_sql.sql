-- Password Vault Database Schema + Sample Data
-- SQLite Compatible
-- Run this file: sqlite3 vault.db < sample_database_sqlite.sql
-- Or use any SQLite GUI tool

-- Drop tables if they exist (for clean restart)
DROP TABLE IF EXISTS vault_entries;
DROP TABLE IF EXISTS users;

-- Create users table
DROP TABLE IF EXISTS vault_entries;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    username TEXT NOT NULL,
    hashed_password TEXT NOT NULL,
    created_at TEXT,
    updated_at TEXT
);

--create vault entries--
CREATE TABLE vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    account TEXT NOT NULL,
    hashed_password TEXT NOT NULL,
    encrypted_data BLOB NOT NULL,
    iv BLOB NOT NULL,
    salt BLOB NOT NULL,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(owner_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Create indexes on vault_entries
CREATE INDEX ix_vault_entries_id ON vault_entries(id);
CREATE INDEX ix_vault_entries_title ON vault_entries(title);
CREATE INDEX ix_vault_entries_user_id ON vault_entries(user_id);

-- Insert sample users
-- Note: These are bcrypt hashes of "password123"
-- All timestamps are ISO 8601 format
INSERT INTO users (email, hashed_password, created_at, updated_at) VALUES
    ('alice@example.com', '$2b$12$KIXn4mGQvzN8eT5PqH7k8.LZx9cP3vY1dR2fE8tG7hS6jK9lM0nO4', '2024-02-22T10:30:00.000Z', '2024-02-22T10:30:00.000Z'),
    ('bob@example.com', '$2b$12$9mHx2pLQk4N7fE6RsM8j3.WXyZ1aB5cD9fG3hI7jK2lM6nO8pQ4rS', '2024-02-23T14:15:00.000Z', '2024-02-23T14:15:00.000Z'),
    ('charlie@example.com', '$2b$12$3nIx5oMRp9L3gF7StN9k4.YZa2bC6dE0fH4iJ8kL3mN7oP9qR5sT', '2024-02-24T09:00:00.000Z', '2024-02-24T09:00:00.000Z');

-- Insert sample vault entries
-- Note: For SQLite, we use X'hex' notation for BLOB data
-- This is fake encrypted data (random hex) - won't decrypt to anything meaningful
INSERT INTO vault_entries (user_id, account, hashed_password, iv, salt, created_at, updated_at) VALUES
    -- Alice's entries (user_id = 1)
    (1, 'Netflix', 
     X'8a4f2c1e89b7d3f0a6c2e8f4b1d7a3c9e5f1b8d4a0c6e2f8b4d0a7c3e9f5b1d8',
     X'7f3e91b2c5d8a4f1e6b3c0d7',
     X'b2d9e7a3f6c1d8b4e0c7a5f2',
     '2024-02-22T11:45:00.000Z', NULL),
    
    (1, 'Gmail',
     X'3c8d91f4b6e2a8c0d7f3b9e5a1c8d4f0b6e2a9c5d1f7b3e9a5c1d8f4b0e6a2c9',
     X'9a2cf8e1b5d4a7c0f3e6b2d9',
     X'4e7ba2d9f6c3e0b8d5a1f7c4',
     '2024-02-22T12:00:00.000Z', NULL),
    
    (1, 'Bank of America',
     X'f1b8d4a0c6e2f9b5d1a8c4e0f7b3d9a5c1e8f4b0d7a3c9e5f1b8d4a0c6e2f8b4',
     X'c0e7a5f2b9d6c3e0a8f5b2d9',
     X'd8b4e0c7a5f2b9e6c3d0a8f5',
     '2024-02-22T14:30:00.000Z', '2024-02-23T09:15:00.000Z'),
    
    -- Bob's entries (user_id = 2)
    (2, 'Twitter',
     X'a5c1e8f4b0d7a3c9e5f1b8d4a0c6e2f8b4d0a7c3e9f5b1d8a4f0c6e2f9b5d1a8',
     X'e6b3c0d7a5f2b9e6c3d0a8f5',
     X'a8f5b2d9e6c3d0b8e5a2f7c4',
     '2024-02-23T15:00:00.000Z', NULL),
    
    (2, 'Amazon',
     X'b6e2a9c5d1f7b3e9a5c1d8f4b0e6a2c9d5f1b7e3a9c5d1f8b4e0a6c2d9f5b1e7',
     X'f3e6b2d9c5a1e8f4b0d7a3c9',
     X'd5a1f7c4b9e6c3d0b8e5a2f7',
     '2024-02-23T15:30:00.000Z', '2024-02-24T10:00:00.000Z'),
    
    -- Charlie's entries (user_id = 3)
    (3, 'LinkedIn',
     X'c7d3e9f5b1d8a4f0c6e2f9b5d1a8c4e0f7b3d9a5c1e8f4b0d7a3c9e5f1b8d4a0',
     X'b0d7a3c9e5f1b8d4a0c6e2f8',
     X'c3d0b8e5a2f7c4d9b6e3a0f7',
     '2024-02-24T09:30:00.000Z', NULL);

-- Verify data was inserted
SELECT 'Users inserted: ' || COUNT(*) as info FROM users;
SELECT 'Vault entries inserted: ' || COUNT(*) as info FROM vault_entries;

-- Show sample data
SELECT 
    u.email,
    COUNT(v.id) as num_vault_entries
FROM users u
LEFT JOIN vault_entries v ON u.id = v.user_id
GROUP BY u.email
ORDER BY u.email;

-- Notes for developers:
-- 1. All sample users have password: "password123"
-- 2. Encrypted data is fake (random hex) - won't decrypt to anything meaningful
-- 3. For real encryption, use Web Crypto API in frontend with actual master password
-- 4. Remember: server never sees master password, only stores encrypted blobs