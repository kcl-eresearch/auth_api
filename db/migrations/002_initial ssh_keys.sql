CREATE TABLE IF NOT EXISTS `ssh_keys` (
  `id` bigint unsigned NOT NULL AUTO_INCREMENT,
  `created_at` timestamp NULL DEFAULT NULL,
  `user_id` bigint unsigned NOT NULL,
  `type` varchar(255) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `name` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `pub_key` varchar(1024) CHARACTER SET ascii COLLATE ascii_general_ci NOT NULL,
  `allowed_ips` json DEFAULT NULL,
  `access_type` enum('sftp','rsync','any','sftp_ro','rsync_ro','rsync_wo') COLLATE utf8mb4_unicode_ci DEFAULT 'any',
  `extra_options` json DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `ssh_keys_pub_key_unique` (`user_id`,`pub_key`),
  CONSTRAINT `ssh_keys_user_id_foreign` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
