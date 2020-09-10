BEGIN TRANSACTION;
DROP TABLE IF EXISTS "Hosts";
CREATE TABLE IF NOT EXISTS "Hosts"
(
    "id"          INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "ip"          TEXT    NOT NULL,
    "mac"         TEXT    NOT NULL,
    "vendor"      INTEGER    NOT NULL,
    "date"        TEXT    NOT NULL,
    "network"     TEXT    NOT NULL
);

DROP TABLE IF EXISTS "Datetime";
CREATE TABLE IF NOT EXISTS "Datetime"
(
    "id"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "date" TEXT    NOT NULL UNIQUE
);
INSERT INTO Datetime(id, date) VALUES (1, "trash");

DROP TABLE IF EXISTS Descriptions;
CREATE TABLE IF NOT EXISTS "Descriptions"
(
    "mac"         TEXT NOT NULL PRIMARY KEY UNIQUE,
    "description" TEXT NOT NULL
);

DROP TABLE IF EXISTS "Vendors";
CREATE TABLE IF NOT EXISTS "Vendors"
(
    "id"   INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT UNIQUE,
    "vendor" TEXT    NOT NULL UNIQUE
);
INSERT INTO Vendors(id, vendor) VALUES (1, "-");

COMMIT;
