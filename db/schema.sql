CREATE TABLE IF NOT EXISTS Usage (
  HardwareAddr BIGINT NOT NULL,
  StartTime TIMESTAMP NOT NULL,
  StopTime TIMESTAMP NOT NULL,
  Egress BIGINT NOT NULL,
  Ingress BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS DnsBlackList (
  Name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS MacBlackList (
  HardwareAddr BIGINT NOT NULL UNIQUE
);
