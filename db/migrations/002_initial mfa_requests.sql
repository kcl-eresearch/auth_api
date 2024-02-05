CREATE TABLE IF NOT EXISTS `mfa_requests` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL,
  `expires_at` timestamp NULL DEFAULT NULL,
  `user_id` bigint unsigned NOT NULL,
  `service` varchar(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `remote_ip` varchar(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `status` enum('pending','approved','rejected') CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL DEFAULT 'pending',
  PRIMARY KEY (`id`),
  KEY `mfa_requests_user_id_service_index` (`user_id`,`service`),
  CONSTRAINT `mfa_requests_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
