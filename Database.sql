CREATE DATABASE IF NOT EXISTS HADROUG_DELIVERY
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE HADROUG_DELIVERY;

CREATE TABLE IF NOT EXISTS admins (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS restaurants (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    phone VARCHAR(30) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    address VARCHAR(500) NULL,
    lat DECIMAL(10,7) NULL,
    lng DECIMAL(10,7) NULL,
    balance_due DECIMAL(12,3) NOT NULL DEFAULT 0.000,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_restaurant_active (is_active)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS drivers (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    phone VARCHAR(30) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    vehicle VARCHAR(50) NOT NULL DEFAULT 'scooter',
    lat DECIMAL(10,7) NULL,
    lng DECIMAL(10,7) NULL,
    last_location_update DATETIME NULL,
    is_online TINYINT(1) NOT NULL DEFAULT 0,
    is_active TINYINT(1) NOT NULL DEFAULT 1,
    current_orders_count TINYINT UNSIGNED NOT NULL DEFAULT 0,
    max_concurrent_orders TINYINT UNSIGNED NOT NULL DEFAULT 1,
    radius DECIMAL(5,2) NOT NULL DEFAULT 2.50,
    driver_points INT NOT NULL DEFAULT 100,
    wallet_balance DECIMAL(12,3) NOT NULL DEFAULT 0.000,
    total_earnings DECIMAL(12,3) NOT NULL DEFAULT 0.000,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_driver_search (is_online, is_active, current_orders_count),
    INDEX idx_driver_location (lat, lng)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS orders (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    restaurant_id BIGINT UNSIGNED NOT NULL,
    driver_id BIGINT UNSIGNED NULL,
    offered_driver_id BIGINT UNSIGNED NULL,

    customer_name VARCHAR(150) NOT NULL,
    customer_phone VARCHAR(30) NOT NULL,
    customer_address VARCHAR(500) NOT NULL,

    pickup_lat DECIMAL(10,7) NOT NULL,
    pickup_lng DECIMAL(10,7) NOT NULL,
    delivery_lat DECIMAL(10,7) NOT NULL,
    delivery_lng DECIMAL(10,7) NOT NULL,

    food_price DECIMAL(12,3) NOT NULL DEFAULT 0.000,
    delivery_fee DECIMAL(12,3) NOT NULL DEFAULT 0.000,
    platform_fee DECIMAL(12,3) NOT NULL DEFAULT 1.000,

    otp_code CHAR(4) NOT NULL,

    status ENUM(
        'pending','offered','accepted','picking_up',
        'delivering','completed','cancelled'
    ) NOT NULL DEFAULT 'pending',

    payment_status ENUM('pending','paid') NOT NULL DEFAULT 'pending',

    offer_expires_at DATETIME NULL,
    accepted_at DATETIME NULL,
    restaurant_paid_at DATETIME NULL,
    pickup_verified_at DATETIME NULL,
    delivery_started_at DATETIME NULL,
    completed_at DATETIME NULL,
    cancelled_at DATETIME NULL,

    platform_fee_recorded TINYINT(1) NOT NULL DEFAULT 0,
    cancellation_reason VARCHAR(500) NULL,

    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    CONSTRAINT fk_orders_restaurant
        FOREIGN KEY (restaurant_id) REFERENCES restaurants(id)
        ON DELETE RESTRICT ON UPDATE CASCADE,

    CONSTRAINT fk_orders_driver
        FOREIGN KEY (driver_id) REFERENCES drivers(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    CONSTRAINT fk_orders_offered_driver
        FOREIGN KEY (offered_driver_id) REFERENCES drivers(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    INDEX idx_orders_restaurant_date (restaurant_id, created_at),
    INDEX idx_orders_driver_status (driver_id, status),
    INDEX idx_orders_dispatch (status, offered_driver_id, offer_expires_at),
    INDEX idx_orders_created (created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS order_dispatch_log (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT UNSIGNED NOT NULL,
    driver_id BIGINT UNSIGNED NOT NULL,
    status ENUM('offered','accepted','rejected','expired') NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_dispatch_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    CONSTRAINT fk_dispatch_driver
        FOREIGN KEY (driver_id) REFERENCES drivers(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    UNIQUE KEY uq_order_driver (order_id, driver_id),
    INDEX idx_dispatch_order_status (order_id, status),
    INDEX idx_dispatch_driver_status (driver_id, status)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS order_status_history (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    order_id BIGINT UNSIGNED NOT NULL,
    old_status VARCHAR(30) NULL,
    new_status VARCHAR(30) NOT NULL,
    changed_by_type ENUM('system','restaurant','driver','admin') NOT NULL,
    changed_by_id BIGINT UNSIGNED NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_history_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
        ON DELETE CASCADE ON UPDATE CASCADE,

    INDEX idx_history_order (order_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS restaurant_transactions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    restaurant_id BIGINT UNSIGNED NOT NULL,
    order_id BIGINT UNSIGNED NULL,
    amount DECIMAL(12,3) NOT NULL,
    type ENUM('platform_fee','payment','adjustment') NOT NULL,
    note VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_restaurant_transaction
        FOREIGN KEY (restaurant_id) REFERENCES restaurants(id)
        ON DELETE RESTRICT ON UPDATE CASCADE,

    CONSTRAINT fk_restaurant_transaction_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    INDEX idx_restaurant_transactions (restaurant_id, created_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS driver_transactions (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    driver_id BIGINT UNSIGNED NOT NULL,
    order_id BIGINT UNSIGNED NULL,
    amount DECIMAL(12,3) NOT NULL,
    type ENUM('delivery_earning','withdrawal','adjustment') NOT NULL,
    note VARCHAR(500) NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_driver_transaction
        FOREIGN KEY (driver_id) REFERENCES drivers(id)
        ON DELETE RESTRICT ON UPDATE CASCADE,

    CONSTRAINT fk_driver_transaction_order
        FOREIGN KEY (order_id) REFERENCES orders(id)
        ON DELETE SET NULL ON UPDATE CASCADE,

    INDEX idx_driver_transactions (driver_id, created_at)
) ENGINE=InnoDB;
