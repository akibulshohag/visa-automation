-- phpMyAdmin SQL Dump
-- version 5.2.1
-- https://www.phpmyadmin.net/
--
-- Host: 127.0.0.1:3306
-- Generation Time: Mar 09, 2026 at 05:00 PM
-- Server version: 9.1.0
-- PHP Version: 8.3.14

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Database: `visa_automation`
--

-- --------------------------------------------------------

--
-- Table structure for table `accounts`
--

DROP TABLE IF EXISTS `accounts`;
CREATE TABLE IF NOT EXISTS `accounts` (
  `id` int NOT NULL AUTO_INCREMENT,
  `phone` varchar(20) NOT NULL,
  `password` varchar(255) NOT NULL,
  `status` varchar(50) DEFAULT 'IDLE',
  `last_run` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `access_token` text,
  `token_expires_at` datetime DEFAULT NULL,
  `name` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `phone` (`phone`)
) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `accounts`
--

INSERT INTO `accounts` (`id`, `phone`, `password`, `status`, `last_run`, `created_at`, `access_token`, `token_expires_at`, `name`) VALUES
(1, '01344838473', 'Pass@123', 'IDLE', '2026-03-09 22:55:39', '2026-03-09 10:17:43', 'eyJraWQiOiJpYW0tand0LXJzYS0xIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJiODVmYTgxZC1mYjJlLTRkNjMtOWFhMi05ZWJiMTYzZjk5NWIiLCJhdWQiOiJpYW1zLWFwaSIsInJvbGVzIjpbXSwiaXNzIjoiaWFtcyIsImV4cCI6MTc3MzA3NjIxNSwiaWF0IjoxNzczMDc1MzE1LCJqdGkiOiI5MTUxYTJhOC1iZjIyLTRhMzQtYmViOC0xOGVmNGUyMDNjOTMiLCJzaWQiOiIzZTVhYzQwYS01MmY3LTRmOWYtODJjMi00YWRmMjFjYjQ3YTQifQ.okBKdix3dNoX7TV9USIZc2fSKxYOAlBncEp40lihUWzhaMs6HOXQz59PSHis1YXMrl9BZtf92CSIxmeXhMoHenKhwg9M--8fIcnEsNyZe8B78rlWnHevsd5jmicwdv2oHetdB2ZzQhQaI93Y4QrA0gWiQqGsVx4MWl9os3wDs81i-fHhRYDiQg3Akrgn_UeKTr-XVNjLKW6NddSy9Y8rkffo7j0dTplA_23OYZZwid_KNJDJaljL-LkwFT6U7qLCJCp4krvUAMtx15E2KA9Qn38Doceafaj19-3ntRIH6P95kHQuPVVQBvYZ94-7QEXnCQNt-cDxhhefa4VyfLgrHQ', '2026-03-09 23:09:16', NULL),
(2, '01345423089', 'Pass@123', 'IDLE', '2026-03-09 22:55:45', '2026-03-09 10:17:43', 'eyJraWQiOiJpYW0tand0LXJzYS0xIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiI1MTU4ZDJlZS03YjI1LTQwYTYtYjcyYy1iZDMzOThlY2VmYmUiLCJhdWQiOiJpYW1zLWFwaSIsInJvbGVzIjpbXSwiaXNzIjoiaWFtcyIsImV4cCI6MTc3MzA3NjIxMywiaWF0IjoxNzczMDc1MzEzLCJqdGkiOiJkMDkzNjkzOS1lNDMxLTRhNGYtYjFlNy0zYzI3NTg5MWU5MDEiLCJzaWQiOiIzNWNjNzk2ZC01MWJlLTRiOTEtOTg2ZC05MWIxYzg4ZDNlMjUifQ.dhssAXWv3ST5tV4dAB_1gnbmOHkSGMrkA8BhxYeoux3TWsb_kukcP7V_t4LdWCwCVb4uzJckInAz9CS4yVSL-T6Lm37ry2SlKdVD_ujh4_7UYlBhZw5i0-BeCKl5U-FHXCZhWFUtCbJW1FuKjQNEpmsxO9R5gZFt7iWn5nPtxWPUWBkX5isu7W17jbwBkK8q3lX9icTcz917NlUtgu_NK1lCgR21ZP4ptqbl3Xk07Q6r8D6sgo_O2zB9bItGig0LuS6RlVzUstrcwbKMbzzMVO7Wi-U1rb3FkOeXQn6PWP8srSS7Q7KQJzuGLQ7RwampqYbjJiQTBby1YHjbdwx8rQ', '2026-03-09 23:09:15', NULL),
(3, '01308993300', 'Pass@123', 'IDLE', '2026-03-09 22:55:43', '2026-03-09 16:17:11', 'eyJraWQiOiJpYW0tand0LXJzYS0xIiwidHlwIjoiSldUIiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJhYWJiY2M2Ni00OTVmLTRjMTMtOWNjYi0wMThkMzQ5NTEwM2IiLCJhdWQiOiJpYW1zLWFwaSIsInJvbGVzIjpbXSwiaXNzIjoiaWFtcyIsImV4cCI6MTc3MzA3NjIxMywiaWF0IjoxNzczMDc1MzEzLCJqdGkiOiI3YzMzNmRlMC0xYTdlLTRiZjktYmY2MS00YmE1NDRlODczM2UiLCJzaWQiOiI1M2UwZDU3ZC0zOTc1LTRmNTgtYjkzOS0wNjZkZGZkYmY1OWUifQ.WHLOi4cabftyd73SvdqY-6pBFKfWTSm8N5cYfm7pN8Mqsoi1bbdZWSTSbWTgKJqYyWB5k9L_iE0Y92Bhk_q2jAIcm8Zl-a9g-fAcTIPWVqwVgO0dQ74tx6gQ73K06z_c9gSHaF9KGp6uLDJJxdjVmE40Bqc46yDqJnSeTpIzcYy6f8dFDjRjyXXEY2cZZJVZIV0cAuRjMCwuPNEi8IyznISpJ5BtdnL1x6rSSBbH5lqTJqDYU1jdrGcaccAggMwfTAo-o8XeLMvGoM29gkWwa6KhnH9BtdsEy5zIr9GwVHmF3F0ExbthgvSbM9kBMXb2S_DGh7-_Bc_6mmhC404BiA', '2026-03-09 23:09:13', NULL);

-- --------------------------------------------------------

--
-- Table structure for table `config`
--

DROP TABLE IF EXISTS `config`;
CREATE TABLE IF NOT EXISTS `config` (
  `key` varchar(100) NOT NULL,
  `value` mediumtext NOT NULL,
  PRIMARY KEY (`key`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `config`
--

INSERT INTO `config` (`key`, `value`) VALUES
('failDelay', '2'),
('maxReserveRetry', '100'),
('maxRetry', '10'),
('reserveTime', '13:32:00'),
('retryDelay', '5'),
('successDelay', '1'),
('paymentInitDelay', '0');

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

DROP TABLE IF EXISTS `logs`;
CREATE TABLE IF NOT EXISTS `logs` (
  `id` bigint NOT NULL AUTO_INCREMENT,
  `phone` varchar(20) NOT NULL,
  `level` varchar(10) NOT NULL,
  `message` text NOT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_phone` (`phone`),
  KEY `idx_created` (`created_at`)
) ENGINE=InnoDB AUTO_INCREMENT=1239 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `logs`
--

INSERT INTO `logs` (`id`, `phone`, `level`, `message`, `created_at`) VALUES
(1163, '01877020969', 'INFO', 'Starting automation (target step: Sign In)', '2026-03-09 16:55:09'),
(1164, '01724659366', 'INFO', 'Starting automation (target step: Sign In)', '2026-03-09 16:55:09'),
(1165, '01308993300', 'INFO', 'Starting automation (target step: Sign In)', '2026-03-09 16:55:09'),
(1166, '01344838473', 'INFO', 'Starting automation (target step: Sign In)', '2026-03-09 16:55:09'),
(1167, '01345423089', 'INFO', 'Starting automation (target step: Sign In)', '2026-03-09 16:55:09'),
(1168, '01877020969', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:09'),
(1169, '01308993300', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:09'),
(1170, '01724659366', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:09'),
(1171, '01345423089', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:09'),
(1172, '01344838473', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:09'),
(1173, '01308993300', 'INFO', '✅ Sign In successful. Token saved.', '2026-03-09 16:55:13'),
(1174, '01308993300', 'WARN', '⏰ Past Reserve Time (13:32:00)! Running OTP in background and advancing immediately.', '2026-03-09 16:55:13'),
(1175, '01308993300', 'INFO', '⏳ Step: Verify OTP — waiting for SMS...', '2026-03-09 16:55:13'),
(1176, '01308993300', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:13'),
(1177, '01345423089', 'INFO', '✅ Sign In successful. Token saved.', '2026-03-09 16:55:14'),
(1178, '01345423089', 'WARN', '⏰ Past Reserve Time (13:32:00)! Running OTP in background and advancing immediately.', '2026-03-09 16:55:14'),
(1179, '01345423089', 'INFO', '⏳ Step: Verify OTP — waiting for SMS...', '2026-03-09 16:55:14'),
(1180, '01345423089', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:14'),
(1181, '01724659366', 'INFO', '✅ Sign In successful. Token saved.', '2026-03-09 16:55:14'),
(1182, '01724659366', 'WARN', '⏰ Past Reserve Time (13:32:00)! Running OTP in background and advancing immediately.', '2026-03-09 16:55:14'),
(1183, '01724659366', 'INFO', '⏳ Step: Verify OTP — waiting for SMS...', '2026-03-09 16:55:14'),
(1184, '01724659366', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:14'),
(1185, '01877020969', 'WARN', 'Sign In failed (401): Invalid credentials. Please try again.', '2026-03-09 16:55:14'),
(1186, '01877020969', 'WARN', 'IP blocked. Rotating proxy...', '2026-03-09 16:55:14'),
(1187, '01308993300', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:15'),
(1188, '01344838473', 'INFO', '✅ Sign In successful. Token saved.', '2026-03-09 16:55:16'),
(1189, '01344838473', 'WARN', '⏰ Past Reserve Time (13:32:00)! Running OTP in background and advancing immediately.', '2026-03-09 16:55:16'),
(1190, '01344838473', 'INFO', '⏳ Step: Verify OTP — waiting for SMS...', '2026-03-09 16:55:16'),
(1191, '01344838473', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:16'),
(1192, '01345423089', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:16'),
(1193, '01724659366', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:17'),
(1194, '01344838473', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:18'),
(1195, '01877020969', 'INFO', 'Step: Sign In...', '2026-03-09 16:55:19'),
(1196, '01724659366', 'INFO', '📱 OTP received: 815265 — verifying...', '2026-03-09 16:55:20'),
(1197, '01724659366', 'INFO', '✅ OTP Verification successful.', '2026-03-09 16:55:20'),
(1198, '01724659366', 'WARN', '⚠️ OTP response had no new accessToken — keeping signin token. Data: {\"verified\":true,\"verificationStatus\":\"OTP verified\",\"expiresAt\":\"2026-03-09T17:00:14.567338Z\"}', '2026-03-09 16:55:20'),
(1199, '01877020969', 'WARN', 'Worker stopped by user.', '2026-03-09 16:55:20'),
(1200, '01308993300', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:20'),
(1201, '01345423089', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:21'),
(1202, '01724659366', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:22'),
(1203, '01877020969', 'WARN', 'Sign In failed (401): Invalid credentials. Please try again.', '2026-03-09 16:55:22'),
(1204, '01877020969', 'WARN', 'IP blocked. Rotating proxy...', '2026-03-09 16:55:22'),
(1205, '01308993300', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:23'),
(1206, '01344838473', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:23'),
(1207, '01724659366', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:24'),
(1208, '01345423089', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:24'),
(1209, '01308993300', 'INFO', '📱 OTP received: 850267 — verifying...', '2026-03-09 16:55:25'),
(1210, '01345423089', 'INFO', '📱 OTP received: 598156 — verifying...', '2026-03-09 16:55:25'),
(1211, '01344838473', 'INFO', '📱 OTP received: 080962 — verifying...', '2026-03-09 16:55:25'),
(1212, '01308993300', 'INFO', '✅ OTP Verification successful.', '2026-03-09 16:55:25'),
(1213, '01308993300', 'WARN', '⚠️ OTP response had no new accessToken — keeping signin token. Data: {\"verified\":true,\"verificationStatus\":\"OTP verified\",\"expiresAt\":\"2026-03-09T17:00:13.061849Z\"}', '2026-03-09 16:55:25'),
(1214, '01345423089', 'INFO', '✅ OTP Verification successful.', '2026-03-09 16:55:26'),
(1215, '01345423089', 'WARN', '⚠️ OTP response had no new accessToken — keeping signin token. Data: {\"verified\":true,\"verificationStatus\":\"OTP verified\",\"expiresAt\":\"2026-03-09T17:00:13.563002Z\"}', '2026-03-09 16:55:26'),
(1216, '01344838473', 'INFO', '✅ OTP Verification successful.', '2026-03-09 16:55:26'),
(1217, '01344838473', 'WARN', '⚠️ OTP response had no new accessToken — keeping signin token. Data: {\"verified\":true,\"verificationStatus\":\"OTP verified\",\"expiresAt\":\"2026-03-09T17:00:15.873856Z\"}', '2026-03-09 16:55:26'),
(1218, '01344838473', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:27'),
(1219, '01877020969', 'WARN', '⏰ Past Reserve Time (13:32:00)! Running OTP in background and advancing immediately.', '2026-03-09 16:55:27'),
(1220, '01877020969', 'INFO', '⏳ Step: Verify OTP — waiting for SMS...', '2026-03-09 16:55:27'),
(1221, '01308993300', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:28'),
(1222, '01724659366', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:29'),
(1223, '01345423089', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:29'),
(1224, '01308993300', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:30'),
(1225, '01724659366', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:31'),
(1226, '01344838473', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:32'),
(1227, '01345423089', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:32'),
(1228, '01344838473', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:34'),
(1229, '01308993300', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:35'),
(1230, '01724659366', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:36'),
(1231, '01345423089', 'INFO', '🎯 Step: Reserve Slot...', '2026-03-09 16:55:37'),
(1232, '01724659366', 'WARN', 'Worker stopped by user.', '2026-03-09 16:55:37'),
(1233, '01308993300', 'WARN', 'Worker stopped by user.', '2026-03-09 16:55:37'),
(1234, '01344838473', 'WARN', 'Worker stopped by user.', '2026-03-09 16:55:37'),
(1235, '01345423089', 'WARN', 'Worker stopped by user.', '2026-03-09 16:55:37'),
(1236, '01308993300', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:38'),
(1237, '01724659366', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:39'),
(1238, '01345423089', 'WARN', 'Reserve error: All slots and payments are disabled. Please try again tomorrow.', '2026-03-09 16:55:40');

-- --------------------------------------------------------

--
-- Table structure for table `proxies`
--

DROP TABLE IF EXISTS `proxies`;
CREATE TABLE IF NOT EXISTS `proxies` (
  `id` int NOT NULL AUTO_INCREMENT,
  `account_id` int NOT NULL,
  `proxy_url` varchar(255) NOT NULL,
  `is_active` tinyint(1) DEFAULT '1',
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `account_id` (`account_id`)
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Dumping data for table `proxies`
--

INSERT INTO `proxies` (`id`, `account_id`, `proxy_url`, `is_active`, `created_at`) VALUES
(1, 1, '160.191.80.162:9001:mukul:11224411', 1, '2026-03-09 10:20:10'),
(2, 2, '160.191.80.163:9002:mukul:11224411', 1, '2026-03-09 10:20:10'),
(3, 3, '144.79.133.99:9014:ashik:11224411', 1, '2026-03-09 16:18:10'),
(4, 3, '144.79.133.99:9014:ashik:11224411', 1, '2026-03-09 16:18:26');

-- --------------------------------------------------------

--
-- Table structure for table `account_files`
-- Per-account PDF documents used by the file-upload step (bytes on disk, metadata here).
--

DROP TABLE IF EXISTS `account_files`;
CREATE TABLE IF NOT EXISTS `account_files` (
  `id` int NOT NULL AUTO_INCREMENT,
  `account_id` int NOT NULL,
  `filename` varchar(255) NOT NULL,
  `mime` varchar(100) DEFAULT NULL,
  `byte_size` int DEFAULT NULL,
  `applicant_index` int DEFAULT '0',
  `is_primary` tinyint(1) DEFAULT '0',
  `web_file_number` varchar(100) DEFAULT NULL,
  `storage_path` varchar(500) NOT NULL,
  `uploaded_at` datetime DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_account` (`account_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

--
-- Constraints for dumped tables
--

--
-- Constraints for table `account_files`
--
ALTER TABLE `account_files`
  ADD CONSTRAINT `account_files_ibfk_1` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`id`) ON DELETE CASCADE;

--
-- Constraints for table `proxies`
--
ALTER TABLE `proxies`
  ADD CONSTRAINT `proxies_ibfk_1` FOREIGN KEY (`account_id`) REFERENCES `accounts` (`id`) ON DELETE CASCADE;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
