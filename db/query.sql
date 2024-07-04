-- name: EnterUsage :exec
INSERT INTO Usage (
  HardwareAddr, StartTime, StopTime, Egress, Ingress
) VALUES (
  $1, $2, $3, $4, $5
);
