CREATE DATABASE IF NOT EXISTS soap;
USE soap;

CREATE TABLE IF NOT EXISTS cart (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  product_id INT DEFAULT NULL,
  total_price DECIMAL(10,2) DEFAULT NULL,
  date_of_order DATE DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS orders (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  user_id INT DEFAULT NULL,
  order_date DATE DEFAULT NULL,
  total_price DECIMAL(10,2) DEFAULT NULL,
  status ENUM('pending', 'shipped', 'delivered') DEFAULT 'pending',
  payment_method VARCHAR(50) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS products (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) DEFAULT NULL,
  description VARCHAR(255) DEFAULT NULL,
  price DECIMAL(10,2) DEFAULT NULL,
  image LONGBLOB DEFAULT NULL,
  category VARCHAR(100) DEFAULT NULL,
  stock INT DEFAULT 0,
  ean VARCHAR(13) DEFAULT NULL,
  brand VARCHAR(100) DEFAULT NULL,
  isAdmin BOOLEAN DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS users (
  id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  firstname VARCHAR(100) DEFAULT NULL,
  lastname VARCHAR(100) DEFAULT NULL,
  email VARCHAR(255) DEFAULT NULL,
  password VARCHAR(255) DEFAULT NULL,
  isAdmin BOOLEAN DEFAULT FALSE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE INDEX idx_cart_product_id ON cart (product_id);
CREATE INDEX idx_cart_date_of_order ON cart (date_of_order);
CREATE INDEX idx_orders_user_id ON orders (user_id);
CREATE INDEX idx_orders_order_date ON orders (order_date);
CREATE INDEX idx_products_name ON products (name);
CREATE INDEX idx_products_description ON products (description);