-- Nexo CRM · esquema para Neon (PostgreSQL)
-- Pegar completo en Neon > SQL Editor y presionar "Run". Se puede ejecutar más de una vez sin romper nada.

CREATE TABLE IF NOT EXISTS sellers (
  "id"           TEXT PRIMARY KEY,
  "createdAt"    TEXT NOT NULL DEFAULT '',
  "updatedAt"    TEXT NOT NULL DEFAULT '',
  "name"         TEXT NOT NULL DEFAULT '',
  "email"        TEXT NOT NULL DEFAULT '',
  "passwordHash" TEXT NOT NULL DEFAULT '',
  "role"         TEXT NOT NULL DEFAULT 'seller',
  "active"       BOOLEAN NOT NULL DEFAULT TRUE
);
CREATE UNIQUE INDEX IF NOT EXISTS sellers_email_uq ON sellers (lower("email"));

CREATE TABLE IF NOT EXISTS contacts (
  "id"        TEXT PRIMARY KEY,
  "createdAt" TEXT NOT NULL DEFAULT '',
  "updatedAt" TEXT NOT NULL DEFAULT '',
  "name"      TEXT NOT NULL DEFAULT '',
  "company"   TEXT NOT NULL DEFAULT '',
  "email"     TEXT NOT NULL DEFAULT '',
  "phone"     TEXT NOT NULL DEFAULT '',
  "status"    TEXT NOT NULL DEFAULT 'Prospecto',
  "source"    TEXT NOT NULL DEFAULT '',
  "owner"     TEXT NOT NULL DEFAULT '',
  "notes"     TEXT NOT NULL DEFAULT '',
  "archived"  BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS opportunities (
  "id"           TEXT PRIMARY KEY,
  "createdAt"    TEXT NOT NULL DEFAULT '',
  "updatedAt"    TEXT NOT NULL DEFAULT '',
  "title"        TEXT NOT NULL DEFAULT '',
  "contactId"    TEXT NOT NULL DEFAULT '',
  "value"        DOUBLE PRECISION NOT NULL DEFAULT 0,
  "stage"        TEXT NOT NULL DEFAULT 'Nuevo',
  "probability"  DOUBLE PRECISION NOT NULL DEFAULT 10,
  "owner"        TEXT NOT NULL DEFAULT '',
  "expectedClose" TEXT NOT NULL DEFAULT '',
  "lastActivity" TEXT NOT NULL DEFAULT '',
  "notes"        TEXT NOT NULL DEFAULT '',
  "lostReason"   TEXT NOT NULL DEFAULT '',
  "archived"     BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS follow_ups (
  "id"            TEXT PRIMARY KEY,
  "createdAt"     TEXT NOT NULL DEFAULT '',
  "updatedAt"     TEXT NOT NULL DEFAULT '',
  "opportunityId" TEXT NOT NULL DEFAULT '',
  "contactId"     TEXT NOT NULL DEFAULT '',
  "title"         TEXT NOT NULL DEFAULT '',
  "dueAt"         TEXT NOT NULL DEFAULT '',
  "type"          TEXT NOT NULL DEFAULT 'Tarea',
  "owner"         TEXT NOT NULL DEFAULT '',
  "status"        TEXT NOT NULL DEFAULT 'Pendiente',
  "notes"         TEXT NOT NULL DEFAULT '',
  "completedAt"   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS conversations (
  "id"            TEXT PRIMARY KEY,
  "createdAt"     TEXT NOT NULL DEFAULT '',
  "contactId"     TEXT NOT NULL DEFAULT '',
  "opportunityId" TEXT NOT NULL DEFAULT '',
  "channel"       TEXT NOT NULL DEFAULT 'Nota',
  "direction"     TEXT NOT NULL DEFAULT 'Nota',
  "summary"       TEXT NOT NULL DEFAULT '',
  "owner"         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS quotes (
  "id"            TEXT PRIMARY KEY,
  "createdAt"     TEXT NOT NULL DEFAULT '',
  "updatedAt"     TEXT NOT NULL DEFAULT '',
  "quoteNumber"   TEXT NOT NULL DEFAULT '',
  "contactId"     TEXT NOT NULL DEFAULT '',
  "opportunityId" TEXT NOT NULL DEFAULT '',
  "subtotal"      DOUBLE PRECISION NOT NULL DEFAULT 0,
  "taxRate"       DOUBLE PRECISION NOT NULL DEFAULT 0,
  "taxAmount"     DOUBLE PRECISION NOT NULL DEFAULT 0,
  "total"         DOUBLE PRECISION NOT NULL DEFAULT 0,
  "currency"      TEXT NOT NULL DEFAULT 'ARS',
  "status"        TEXT NOT NULL DEFAULT 'Borrador',
  "validUntil"    TEXT NOT NULL DEFAULT '',
  "itemsJson"     TEXT NOT NULL DEFAULT '[]',
  "notes"         TEXT NOT NULL DEFAULT '',
  "owner"         TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
  "key"   TEXT PRIMARY KEY,
  "value" TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS counters (
  "key"   TEXT PRIMARY KEY,
  "value" INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sessions (
  "tokenHash" TEXT PRIMARY KEY,
  "sellerId"  TEXT NOT NULL,
  "expiresAt" TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions ("expiresAt");

CREATE TABLE IF NOT EXISTS login_attempts (
  "id"    BIGSERIAL PRIMARY KEY,
  "email" TEXT NOT NULL,
  "at"    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS login_attempts_email_idx ON login_attempts ("email", "at");

INSERT INTO settings ("key", "value") VALUES ('staleDays', '7')
  ON CONFLICT ("key") DO NOTHING;
INSERT INTO settings ("key", "value") VALUES ('companyName', 'Mi empresa')
  ON CONFLICT ("key") DO NOTHING;
