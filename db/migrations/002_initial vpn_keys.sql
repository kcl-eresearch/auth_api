CREATE TABLE IF NOT EXISTS `vpn_keys` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` timestamp NULL DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `user_id` bigint unsigned NOT NULL,
  `uuid` varchar(36) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `public_cert` text CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `status` enum('active','revoked') CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL DEFAULT 'active',
  PRIMARY KEY (`id`),
  UNIQUE KEY `vpn_keys_uuid_unique` (`uuid`),
  KEY `vpn_device_user_id_status_index` (`user_id`,`status`),
  CONSTRAINT `vpn_device_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
