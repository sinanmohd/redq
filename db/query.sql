-- name: EnterUsage :exec
INSERT INTO Usage (
  HardwareAddr, StartTime, StopTime, Egress, Ingress
) VALUES (
  $1, $2, $3, $4, $5
);

-- name: GetUsage :one
SELECT SUM(Ingress) AS Ingress, SUM(Egress) AS Egress FROM Usage;
