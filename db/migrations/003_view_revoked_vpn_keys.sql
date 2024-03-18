CREATE VIEW revoked_vpn_keys AS SELECT vpn_keys.public_cert AS cert, vpn_keys.revoked_at AS cert_revoked_at, users.deleted_at AS user_deleted_at FROM vpn_keys INNER JOIN users ON vpn_keys.user_id = users.id WHERE (vpn_keys.status = "revoked" OR users.deleted_at IS NOT NULL) AND expires_at > NOW();

