-- name: EnterUsage :exec
INSERT INTO Usage (
  HardwareAddr, StartTime, StopTime, Egress, Ingress
) VALUES (
  $1, $2, $3, $4, $5
);

-- name: GetUsage :one
SELECT SUM(Ingress) AS Ingress, SUM(Egress) AS Egress
FROM Usage;

-- name: EnterDnsBlackList :exec
INSERT INTO DnsBlackList (
  Name
) VALUES (
  $1
);

-- name: GetDnsBlackList :many
SELECT *
FROM DnsBlackList;
