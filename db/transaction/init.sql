-- transaction-service schema.

CREATE TABLE IF NOT EXISTS accounts (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER NOT NULL,
    account_number VARCHAR(32) UNIQUE NOT NULL,
    balance NUMERIC(14, 2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS transactions (
    id SERIAL PRIMARY KEY,
    from_account INTEGER REFERENCES accounts(id),
    to_account INTEGER REFERENCES accounts(id),
    amount NUMERIC(14, 2) NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS cards (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER,
    card_number VARCHAR(32),
    internal_limit NUMERIC(14, 2) DEFAULT 500,
    is_corporate BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- owner_id values match the users table in auth-db.
INSERT INTO accounts (owner_id, account_number, balance) VALUES
    (1, 'ACC-ADMIN-001', 999999.00),
    (2, 'ACC-ALICE-001',   5420.00),
    (3, 'ACC-BOB-001',     1200.00)
ON CONFLICT (account_number) DO NOTHING;

INSERT INTO transactions (from_account, to_account, amount, notes) VALUES
    (2, 3,  50.00, 'Dinner split'),
    (3, 2, 120.00, 'Repayment');
