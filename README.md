# HADROUG DELIVERY 🚀

A comprehensive, real-time food delivery platform architecture and backend system designed for automated order dispatch, multi-role user dashboards, and live tracking. Built with Node.js, Express, Socket.io, and MySQL.

## System Architecture & Workflow 🔄

### 1. Multi-Role Interfaces
* **Admin Dashboard:** System-wide monitoring of total restaurants, active drivers, daily orders, daily income, and cumulative restaurant dues.
* **Restaurant Dashboard:** Daily operational summary showing available drivers, daily order counts, and amounts owed, featuring a live interactive map for driver tracking and a complete order details ledger.
* **Driver Dashboard:** Daily summary tracking completed orders and daily earnings, featuring routing maps, dual-order handling capabilities, and a comprehensive historical order ledger.

### 2. Automated Smart Dispatch Engine
* **Proximity Matching:** When a restaurant publishes a delivery order, the system calculates geographic distances and targets the nearest available driver.
* **Timed Push Offers:** The target driver receives a real-time notification with a **20-second countdown timer** to accept or reject the order.
* **Failover Mechanism:** If the driver rejects or ignores the request within the time limit, the system automatically routes the offer to the next closest eligible driver down the queue.
* **Concurrent Multi-Order Logic:** When all drivers are busy, eligible drivers can take up to two concurrent orders under strict geographic constraints (ensuring the second customer is close enough to maintain swift delivery times), processed through the same timed dispatch protocol.

### 3. Secure Verification & Financial Workflow
* **OTP Verification:** Upon accepting an order, the system generates a **4-digit OTP code**. When the driver arrives at the restaurant, they input this code to verify the pickup and kick off the process.
* **Cash Flow & Settlements:** 
  * The driver pays the restaurant for the food cost upon pickup.
  * A flat **1 TND platform fee** applies.
  * Upon delivery, the driver collects the food cost and their delivery earnings directly from the customer.
  * Comprehensive transaction logging tracks restaurant balances, driver earnings, and platform fees.

## Tech Stack 🛠️
* **Backend:** Node.js, Express.js
* **Real-time Communication:** Socket.io (Rooms for drivers, restaurants, and admins)
* **Database:** MySQL (`InnoDB` with spatial indexing and strict transactional isolation)
* **Security & Middleware:** Bcrypt, JSON Web Tokens (JWT), Helmet, Express Rate Limit
