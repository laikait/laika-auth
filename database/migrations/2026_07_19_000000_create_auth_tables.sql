-- Migration: create_auth_tokens_and_oauth_accounts_tables

CREATE TABLE auth_tokens (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    guard VARCHAR(50) NOT NULL,
    browser VARCHAR(255) NULL,
    ip VARCHAR(45) NULL,
    user_agent TEXT NULL,
    token VARCHAR(255) NOT NULL,
    refresh_token VARCHAR(255) NULL,
    expires_at DATETIME NULL,
    revoked_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    INDEX idx_user_guard (user_id, guard),
    UNIQUE KEY uk_token (token)
) ENGINE=InnoDB;

CREATE TABLE oauth_accounts (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id BIGINT UNSIGNED NOT NULL,
    provider VARCHAR(30) NOT NULL,
    provider_user_id VARCHAR(255) NOT NULL,
    access_token TEXT NULL,
    refresh_token TEXT NULL,
    avatar VARCHAR(255) NULL,
    email VARCHAR(255) NULL,
    expires_at DATETIME NULL,
    created_at DATETIME NOT NULL,
    UNIQUE KEY uk_provider_user (provider, provider_user_id)
) ENGINE=InnoDB;
