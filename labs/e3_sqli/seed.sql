-- E3 SQL Injection lab schema + seed + least-privilege role.
-- DEMO / LOCAL ONLY. Scope section 0: isolated project-owned DB only.
-- Trust boundary TB-C (code/data boundary + database authorization).

-- ---------- IoT-search tables (reader is allowed to read these) ----------
DROP TABLE IF EXISTS telemetry;
DROP TABLE IF EXISTS devices;
-- ---------- Sensitive tables (reader must NOT be able to read) ----------
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS secrets;
DROP TABLE IF EXISTS audit_internal;

CREATE TABLE devices (
    id       SERIAL PRIMARY KEY,
    name     TEXT NOT NULL,
    location TEXT NOT NULL,
    status   TEXT NOT NULL DEFAULT 'active'
);

CREATE TABLE telemetry (
    id         SERIAL PRIMARY KEY,
    device_id  INTEGER NOT NULL REFERENCES devices(id),
    metric     TEXT NOT NULL,
    value      DOUBLE PRECISION NOT NULL
);

CREATE TABLE users (
    id       SERIAL PRIMARY KEY,
    username TEXT NOT NULL,
    password TEXT NOT NULL  -- DEMO ONLY, not a real credential
);

CREATE TABLE secrets (
    id    SERIAL PRIMARY KEY,
    name  TEXT NOT NULL,
    value TEXT NOT NULL
);

CREATE TABLE audit_internal (
    id      SERIAL PRIMARY KEY,
    actor   TEXT NOT NULL,
    action  TEXT NOT NULL
);

INSERT INTO devices (name, location, status) VALUES
    ('sensor-alpha',  'warehouse-1', 'active'),
    ('sensor-beta',   'warehouse-1', 'active'),
    ('gateway-north', 'warehouse-2', 'active'),
    ('pump-01',       'plant-floor', 'maintenance');

INSERT INTO telemetry (device_id, metric, value) VALUES
    (1, 'temperature', 21.4),
    (1, 'humidity',    48.0),
    (2, 'temperature', 22.1),
    (3, 'uptime',      99.9);

INSERT INTO users (username, password) VALUES
    ('admin', 'DEMO_LOCAL_ONLY_admin_pw'),
    ('operator', 'DEMO_LOCAL_ONLY_operator_pw');

INSERT INTO secrets (name, value) VALUES
    ('device_hmac_master', 'DEMO_LOCAL_ONLY_master_secret');

INSERT INTO audit_internal (actor, action) VALUES
    ('system', 'bootstrap');

-- ---------- Least-privilege role (spec section 25) ----------
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'iot_search_reader') THEN
        CREATE ROLE iot_search_reader LOGIN PASSWORD 'DEMO_LOCAL_ONLY_reader_pw';
    END IF;
END $$;

-- Strip everything, then grant ONLY the IoT-search read surface.
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM iot_search_reader;
GRANT USAGE ON SCHEMA public TO iot_search_reader;
GRANT SELECT ON devices   TO iot_search_reader;
GRANT SELECT ON telemetry TO iot_search_reader;
-- Intentionally NO privileges on users / secrets / audit_internal,
-- and NO UPDATE / DELETE / INSERT / TRUNCATE / DROP anywhere.
