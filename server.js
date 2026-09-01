require("dotenv").config();

const express = require("express");
const http = require("http");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const mysql = require("mysql2/promise");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);

/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    console.error(
        "ERROR: JWT_SECRET must exist in .env and contain at least 32 characters."
    );
    process.exit(1);
}

/* =========================================================
   SOCKET.IO
========================================================= */

const io = new Server(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE"]
    }
});

/* =========================================================
   EXPRESS
========================================================= */

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    cors({
        origin: "*",
        methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
        allowedHeaders: ["Content-Type", "Authorization"]
    })
);

app.use(express.json({ limit: "100kb" }));

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false
});

const generalLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 300,
    standardHeaders: true,
    legacyHeaders: false
});

app.use(generalLimiter);

/* =========================================================
   MYSQL
========================================================= */

const pool = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "HADROUG_DELIVERY",

    waitForConnections: true,
    connectionLimit: Number(
        process.env.DB_CONNECTION_LIMIT || 10
    ),
    queueLimit: 0,

    charset: "utf8mb4",

    decimalNumbers: true
});

/* =========================================================
   HELPERS
========================================================= */

function sendError(res, status, message) {
    return res.status(status).json({
        success: false,
        message
    });
}

function sendSuccess(res, data = {}) {
    return res.json({
        success: true,
        ...data
    });
}

function isValidCoordinate(lat, lng) {
    const latitude = Number(lat);
    const longitude = Number(lng);

    return (
        Number.isFinite(latitude) &&
        Number.isFinite(longitude) &&
        latitude >= -90 &&
        latitude <= 90 &&
        longitude >= -180 &&
        longitude <= 180
    );
}

function isValidPhone(phone) {
    return (
        typeof phone === "string" &&
        phone.trim().length >= 6 &&
        phone.trim().length <= 30
    );
}

function generateOTP() {
    return String(
        Math.floor(1000 + Math.random() * 9000)
    );
}

function generateToken(user) {
    return jwt.sign(
        {
            id: Number(user.id),
            role: user.role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

/* =========================================================
   DISTANCE - HAVERSINE
========================================================= */

function calculateDistance(
    lat1,
    lng1,
    lat2,
    lng2
) {
    const R = 6371;

    const p1 =
        Number(lat1) * Math.PI / 180;

    const p2 =
        Number(lat2) * Math.PI / 180;

    const dp =
        (
            Number(lat2) -
            Number(lat1)
        ) *
        Math.PI /
        180;

    const dl =
        (
            Number(lng2) -
            Number(lng1)
        ) *
        Math.PI /
        180;

    const a =
        Math.sin(dp / 2) ** 2 +
        Math.cos(p1) *
        Math.cos(p2) *
        Math.sin(dl / 2) ** 2;

    return (
        R *
        2 *
        Math.atan2(
            Math.sqrt(a),
            Math.sqrt(1 - a)
        )
    );
}

/* =========================================================
   AUTHENTICATION
========================================================= */

async function authenticate(req, res, next) {
    try {
        const header =
            req.headers.authorization;

        if (
            !header ||
            !header.startsWith("Bearer ")
        ) {
            return sendError(
                res,
                401,
                "Authentication required."
            );
        }

        const token =
            header.substring(7);

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        req.user = decoded;

        next();
    } catch (_) {
        return sendError(
            res,
            401,
            "Invalid or expired token."
        );
    }
}

function requireRole(...roles) {
    return (req, res, next) => {
        if (
            !req.user ||
            !roles.includes(req.user.role)
        ) {
            return sendError(
                res,
                403,
                "Access denied."
            );
        }

        next();
    };
}

/* =========================================================
   DATABASE HELPERS
========================================================= */

async function getRestaurantById(
    id,
    connection = pool
) {
    const [rows] =
        await connection.execute(
            `
            SELECT *
            FROM restaurants
            WHERE id = ?
            LIMIT 1
            `,
            [id]
        );

    return rows[0] || null;
}

async function getDriverById(
    id,
    connection = pool
) {
    const [rows] =
        await connection.execute(
            `
            SELECT *
            FROM drivers
            WHERE id = ?
            LIMIT 1
            `,
            [id]
        );

    return rows[0] || null;
}

async function getOrderById(
    id,
    connection = pool
) {
    const [rows] =
        await connection.execute(
            `
            SELECT *
            FROM orders
            WHERE id = ?
            LIMIT 1
            `,
            [id]
        );

    return rows[0] || null;
}

/* =========================================================
   STATUS HISTORY
========================================================= */

async function addStatusHistory(
    connection,
    orderId,
    oldStatus,
    newStatus,
    changedByType,
    changedById = null
) {
    await connection.execute(
        `
        INSERT INTO order_status_history
        (
            order_id,
            old_status,
            new_status,
            changed_by_type,
            changed_by_id
        )
        VALUES (?, ?, ?, ?, ?)
        `,
        [
            orderId,
            oldStatus,
            newStatus,
            changedByType,
            changedById
        ]
    );
}

/* =========================================================
   SOCKET HELPERS
========================================================= */

function restaurantRoom(id) {
    return `restaurant:${id}`;
}

function driverRoom(id) {
    return `driver:${id}`;
}

function adminRoom() {
    return "admins";
}

function emitOrderUpdate(order) {
    if (!order) return;

    io.to(
        restaurantRoom(order.restaurant_id)
    ).emit(
        "order:update",
        order
    );

    if (order.driver_id) {
        io.to(
            driverRoom(order.driver_id)
        ).emit(
            "order:update",
            order
        );
    }

    if (order.offered_driver_id) {
        io.to(
            driverRoom(order.offered_driver_id)
        ).emit(
            "order:update",
            order
        );
    }

    io.to(adminRoom())
        .emit(
            "order:update",
            order
        );
}

function emitDriverUpdate(driver) {
    if (!driver) return;

    io.to(adminRoom())
        .emit(
            "driver:update",
            driver
        );
}

/* =========================================================
   HEALTH
========================================================= */

app.get("/", (req, res) => {
    res.json({
        success: true,
        name: "HADROUG DELIVERY API",
        version: "1.1.0",
        status: "online"
    });
});

app.get(
    "/health",
    async (req, res) => {
        try {
            await pool.query("SELECT 1");

            res.json({
                success: true,
                server: "online",
                database: "connected",
                time: new Date()
            });
        } catch (error) {
            console.error(error);

            res.status(500).json({
                success: false,
                server: "online",
                database: "offline"
            });
        }
    }
);

/* =========================================================
   AUTH - RESTAURANT
========================================================= */

app.post(
    "/api/auth/restaurant/login",
    authLimiter,
    async (req, res) => {
        try {
            const {
                phone,
                password
            } = req.body;

            if (
                !isValidPhone(phone) ||
                !password
            ) {
                return sendError(
                    res,
                    400,
                    "Phone and password are required."
                );
            }

            const [rows] =
                await pool.execute(
                    `
                    SELECT *
                    FROM restaurants
                    WHERE phone = ?
                    LIMIT 1
                    `,
                    [phone.trim()]
                );

            const restaurant =
                rows[0];

            if (!restaurant) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            if (!restaurant.is_active) {
                return sendError(
                    res,
                    403,
                    "Restaurant is inactive."
                );
            }

            const valid =
                await bcrypt.compare(
                    password,
                    restaurant.password_hash
                );

            if (!valid) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            const token =
                generateToken({
                    id: restaurant.id,
                    role: "restaurant"
                });

            delete restaurant.password_hash;

            return sendSuccess(res, {
                token,
                user: restaurant
            });
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Login failed."
            );
        }
    }
);

/* =========================================================
   AUTH - DRIVER
========================================================= */

app.post(
    "/api/auth/driver/login",
    authLimiter,
    async (req, res) => {
        try {
            const {
                phone,
                password
            } = req.body;

            if (
                !isValidPhone(phone) ||
                !password
            ) {
                return sendError(
                    res,
                    400,
                    "Phone and password are required."
                );
            }

            const [rows] =
                await pool.execute(
                    `
                    SELECT *
                    FROM drivers
                    WHERE phone = ?
                    LIMIT 1
                    `,
                    [phone.trim()]
                );

            const driver =
                rows[0];

            if (!driver) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            if (!driver.is_active) {
                return sendError(
                    res,
                    403,
                    "Driver is inactive."
                );
            }

            const valid =
                await bcrypt.compare(
                    password,
                    driver.password_hash
                );

            if (!valid) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            const token =
                generateToken({
                    id: driver.id,
                    role: "driver"
                });

            delete driver.password_hash;

            return sendSuccess(res, {
                token,
                user: driver
            });
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Login failed."
            );
        }
    }
);

/* =========================================================
   AUTH - ADMIN
========================================================= */

app.post(
    "/api/auth/admin/login",
    authLimiter,
    async (req, res) => {
        try {
            const {
                username,
                password
            } = req.body;

            if (!username || !password) {
                return sendError(
                    res,
                    400,
                    "Username and password are required."
                );
            }

            const [rows] =
                await pool.execute(
                    `
                    SELECT *
                    FROM admins
                    WHERE username = ?
                    LIMIT 1
                    `,
                    [username.trim()]
                );

            const admin =
                rows[0];

            if (!admin) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            if (!admin.is_active) {
                return sendError(
                    res,
                    403,
                    "Admin is inactive."
                );
            }

            const valid =
                await bcrypt.compare(
                    password,
                    admin.password_hash
                );

            if (!valid) {
                return sendError(
                    res,
                    401,
                    "Invalid credentials."
                );
            }

            const token =
                generateToken({
                    id: admin.id,
                    role: "admin"
                });

            delete admin.password_hash;

            return sendSuccess(res, {
                token,
                user: admin
            });
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Login failed."
            );
        }
    }
);
/* =========================================================
   ADMIN - CREATE RESTAURANT
========================================================= */

app.post(
    "/api/admin/restaurants",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                name,
                phone,
                password,
                address,
                lat,
                lng
            } = req.body;

            if (
                !name ||
                !phone ||
                !password
            ) {
                return sendError(
                    res,
                    400,
                    "Name, phone and password are required."
                );
            }

            if (
                lat !== undefined ||
                lng !== undefined
            ) {
                if (
                    !isValidCoordinate(
                        lat,
                        lng
                    )
                ) {
                    return sendError(
                        res,
                        400,
                        "Invalid restaurant coordinates."
                    );
                }
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const [result] =
                await pool.execute(
                    `
                    INSERT INTO restaurants
                    (
                        name,
                        phone,
                        password_hash,
                        address,
                        lat,
                        lng
                    )
                    VALUES (?, ?, ?, ?, ?, ?)
                    `,
                    [
                        name.trim(),
                        phone.trim(),
                        passwordHash,
                        address
                            ? String(address).trim()
                            : null,
                        lat ?? null,
                        lng ?? null
                    ]
                );

            return sendSuccess(res, {
                message:
                    "Restaurant created.",
                restaurant_id:
                    result.insertId
            });
        } catch (error) {
            console.error(error);

            if (
                error.code ===
                "ER_DUP_ENTRY"
            ) {
                return sendError(
                    res,
                    409,
                    "Restaurant phone already exists."
                );
            }

            return sendError(
                res,
                500,
                "Could not create restaurant."
            );
        }
    }
);

/* =========================================================
   ADMIN - CREATE DRIVER
========================================================= */

app.post(
    "/api/admin/drivers",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const {
                name,
                phone,
                password,
                vehicle,
                radius,
                max_concurrent_orders
            } = req.body;

            if (
                !name ||
                !phone ||
                !password
            ) {
                return sendError(
                    res,
                    400,
                    "Name, phone and password are required."
                );
            }

            let maxOrders =
                Number(
                    max_concurrent_orders ?? 1
                );

            if (
                !Number.isInteger(
                    maxOrders
                )
            ) {
                maxOrders = 1;
            }

            maxOrders =
                Math.max(
                    1,
                    Math.min(
                        maxOrders,
                        2
                    )
                );

            const driverRadius =
                Number(
                    radius ?? 2.5
                );

            if (
                !Number.isFinite(
                    driverRadius
                ) ||
                driverRadius <= 0 ||
                driverRadius > 20
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid driver radius."
                );
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const [result] =
                await pool.execute(
                    `
                    INSERT INTO drivers
                    (
                        name,
                        phone,
                        password_hash,
                        vehicle,
                        radius,
                        max_concurrent_orders,
                        driver_points
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 100)
                    `,
                    [
                        name.trim(),
                        phone.trim(),
                        passwordHash,
                        vehicle ||
                            "scooter",
                        driverRadius,
                        maxOrders
                    ]
                );

            return sendSuccess(res, {
                message:
                    "Driver created.",
                driver_id:
                    result.insertId
            });
        } catch (error) {
            console.error(error);

            if (
                error.code ===
                "ER_DUP_ENTRY"
            ) {
                return sendError(
                    res,
                    409,
                    "Driver phone already exists."
                );
            }

            return sendError(
                res,
                500,
                "Could not create driver."
            );
        }
    }
);

/* =========================================================
   DRIVER ONLINE / OFFLINE
========================================================= */

app.post(
    "/api/driver/status",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            const online =
                Boolean(req.body.online);

            const [result] =
                await pool.execute(
                    `
                    UPDATE drivers
                    SET is_online = ?
                    WHERE id = ?
                    AND is_active = 1
                    `,
                    [
                        online ? 1 : 0,
                        req.user.id
                    ]
                );

            if (
                result.affectedRows === 0
            ) {
                return sendError(
                    res,
                    404,
                    "Driver not found."
                );
            }

            const driver =
                await getDriverById(
                    req.user.id
                );

            emitDriverUpdate(driver);

            return sendSuccess(res, {
                online,
                driver
            });
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not update driver status."
            );
        }
    }
);

/* =========================================================
   DRIVER LOCATION
========================================================= */

async function updateDriverLocation(
    driverId,
    lat,
    lng
) {
    if (
        !isValidCoordinate(
            lat,
            lng
        )
    ) {
        return false;
    }

    const [result] =
        await pool.execute(
            `
            UPDATE drivers
            SET
                lat = ?,
                lng = ?,
                last_location_update = NOW()
            WHERE id = ?
            AND is_active = 1
            `,
            [
                Number(lat),
                Number(lng),
                driverId
            ]
        );

    return result.affectedRows > 0;
}

async function broadcastDriverLocation(
    driverId,
    lat,
    lng
) {
    const [orders] =
        await pool.execute(
            `
            SELECT
                id,
                restaurant_id
            FROM orders
            WHERE driver_id = ?
            AND status IN
            (
                'accepted',
                'picking_up',
                'delivering'
            )
            `,
            [driverId]
        );

    for (const order of orders) {
        io.to(
            restaurantRoom(
                order.restaurant_id
            )
        ).emit(
            "driver:location",
            {
                driver_id: driverId,
                order_id: order.id,
                lat: Number(lat),
                lng: Number(lng)
            }
        );
    }

    io.to(adminRoom())
        .emit(
            "driver:location",
            {
                driver_id: driverId,
                lat: Number(lat),
                lng: Number(lng)
            }
        );
}

app.post(
    "/api/driver/location",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            const {
                lat,
                lng
            } = req.body;

            if (
                !isValidCoordinate(
                    lat,
                    lng
                )
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid coordinates."
                );
            }

            const updated =
                await updateDriverLocation(
                    req.user.id,
                    lat,
                    lng
                );

            if (!updated) {
                return sendError(
                    res,
                    404,
                    "Driver not found."
                );
            }

            const driver =
                await getDriverById(
                    req.user.id
                );

            emitDriverUpdate(driver);

            await broadcastDriverLocation(
                req.user.id,
                lat,
                lng
            );

            return sendSuccess(res, {
                message:
                    "Location updated."
            });
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not update location."
            );
        }
    }
);

/* =========================================================
   CREATE ORDER
========================================================= */

app.post(
    "/api/orders",
    authenticate,
    requireRole("restaurant"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const {
                customer_name,
                customer_phone,
                customer_address,
                delivery_lat,
                delivery_lng,
                food_price,
                delivery_fee
            } = req.body;

            if (
                !customer_name ||
                !customer_phone ||
                !customer_address
            ) {
                connection.release();

                return sendError(
                    res,
                    400,
                    "Customer information is required."
                );
            }

            if (
                !isValidCoordinate(
                    delivery_lat,
                    delivery_lng
                )
            ) {
                connection.release();

                return sendError(
                    res,
                    400,
                    "Invalid delivery coordinates."
                );
            }

            const restaurant =
                await getRestaurantById(
                    req.user.id,
                    connection
                );

            if (!restaurant) {
                connection.release();

                return sendError(
                    res,
                    404,
                    "Restaurant not found."
                );
            }

            if (!restaurant.is_active) {
                connection.release();

                return sendError(
                    res,
                    403,
                    "Restaurant is inactive."
                );
            }

            if (
                !isValidCoordinate(
                    restaurant.lat,
                    restaurant.lng
                )
            ) {
                connection.release();

                return sendError(
                    res,
                    400,
                    "Restaurant location is not configured."
                );
            }

            const food =
                Number(
                    food_price ?? 0
                );

            const delivery =
                Number(
                    delivery_fee ?? 0
                );

            if (
                !Number.isFinite(food) ||
                food < 0 ||
                !Number.isFinite(delivery) ||
                delivery < 0
            ) {
                connection.release();

                return sendError(
                    res,
                    400,
                    "Invalid price."
                );
            }

            const otp =
                generateOTP();

            await connection.beginTransaction();

            const [result] =
                await connection.execute(
                    `
                    INSERT INTO orders
                    (
                        restaurant_id,
                        customer_name,
                        customer_phone,
                        customer_address,

                        pickup_lat,
                        pickup_lng,

                        delivery_lat,
                        delivery_lng,

                        food_price,
                        delivery_fee,
                        platform_fee,

                        otp_code,
                        status,
                        payment_status,
                        platform_fee_recorded
                    )
                    VALUES
                    (
                        ?, ?, ?, ?,
                        ?, ?,
                        ?, ?,
                        ?, ?, 1.000,
                        ?, 'pending', 'pending', 0
                    )
                    `,
                    [
                        restaurant.id,
                        String(
                            customer_name
                        ).trim(),
                        String(
                            customer_phone
                        ).trim(),
                        String(
                            customer_address
                        ).trim(),

                        Number(
                            restaurant.lat
                        ),
                        Number(
                            restaurant.lng
                        ),

                        Number(
                            delivery_lat
                        ),
                        Number(
                            delivery_lng
                        ),

                        food,
                        delivery,

                        otp
                    ]
                );

            const orderId =
                result.insertId;

            await addStatusHistory(
                connection,
                orderId,
                null,
                "pending",
                "restaurant",
                restaurant.id
            );

            await connection.commit();

            connection.release();

            const order =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(order);

            processOrderDispatch(
                orderId
            ).catch(console.error);

            return sendSuccess(res, {
                message:
                    "Order created.",
                order
            });
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            connection.release();

            console.error(error);

            return sendError(
                res,
                500,
                "Could not create order."
            );
        }
    }
);
/* =========================================================
   DISPATCH CONFIG
========================================================= */

const OFFER_DURATION_MS = 20 * 1000;

const MAX_DRIVER_LOCATION_AGE_SECONDS = 60;

const SECOND_ORDER_MAX_DISTANCE_KM = 2.0;

/*
  Prevent two local dispatch workers
  from processing the same order.
*/
const dispatchLocks = new Set();

/* =========================================================
   FIND ELIGIBLE DRIVERS
========================================================= */

async function findEligibleDrivers(
    order,
    connection = pool
) {
    const [drivers] =
        await connection.execute(
            `
            SELECT *
            FROM drivers
            WHERE
                is_online = 1
                AND is_active = 1
                AND lat IS NOT NULL
                AND lng IS NOT NULL

                AND last_location_update IS NOT NULL

                AND last_location_update >=
                    NOW() -
                    INTERVAL ${MAX_DRIVER_LOCATION_AGE_SECONDS}
                    SECOND

                AND current_orders_count <
                    max_concurrent_orders
            `
        );

    const eligible = [];

    for (const driver of drivers) {
        const distance =
            calculateDistance(
                order.pickup_lat,
                order.pickup_lng,
                driver.lat,
                driver.lng
            );

        const allowedRadius =
            Math.min(
                Number(
                    driver.radius || 2.5
                ),
                20
            );

        if (
            distance >
            allowedRadius
        ) {
            continue;
        }

        /*
          SECOND ORDER RULE
        */

        if (
            Number(
                driver.current_orders_count
            ) >= 1
        ) {
            if (
                Number(
                    driver.max_concurrent_orders
                ) < 2
            ) {
                continue;
            }

            const [
                activeOrders
            ] =
                await connection.execute(
                    `
                    SELECT
                        id,
                        delivery_lat,
                        delivery_lng
                    FROM orders
                    WHERE driver_id = ?
                    AND status IN
                    (
                        'accepted',
                        'picking_up',
                        'delivering'
                    )
                    `,
                    [driver.id]
                );

            if (
                activeOrders.length === 0
            ) {
                continue;
            }

            let closeToExisting =
                false;

            for (
                const active
                of activeOrders
            ) {
                if (
                    !isValidCoordinate(
                        active.delivery_lat,
                        active.delivery_lng
                    )
                ) {
                    continue;
                }

                const distanceBetweenCustomers =
                    calculateDistance(
                        active.delivery_lat,
                        active.delivery_lng,
                        order.delivery_lat,
                        order.delivery_lng
                    );

                if (
                    distanceBetweenCustomers <=
                    SECOND_ORDER_MAX_DISTANCE_KM
                ) {
                    closeToExisting = true;
                    break;
                }
            }

            if (
                !closeToExisting
            ) {
                continue;
            }
        }

        /*
          NEVER offer the same order
          to the same driver twice.
        */

        const [previous] =
            await connection.execute(
                `
                SELECT id
                FROM order_dispatch_log
                WHERE order_id = ?
                AND driver_id = ?
                LIMIT 1
                `,
                [
                    order.id,
                    driver.id
                ]
            );

        if (
            previous.length > 0
        ) {
            continue;
        }

        eligible.push({
            ...driver,
            distance
        });
    }

    eligible.sort(
        (a, b) =>
            Number(a.distance) -
            Number(b.distance)
    );

    return eligible;
}

/* =========================================================
   PROCESS ORDER DISPATCH
========================================================= */

async function processOrderDispatch(
    orderId
) {
    const id =
        Number(orderId);

    if (
        !Number.isInteger(id) ||
        id <= 0
    ) {
        return;
    }

    if (
        dispatchLocks.has(id)
    ) {
        return;
    }

    dispatchLocks.add(id);

    try {
        const connection =
            await pool.getConnection();

        try {
            await connection.beginTransaction();

            /*
              Lock order.
            */

            const [rows] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [id]
                );

            const order =
                rows[0];

            if (!order) {
                await connection.rollback();
                return;
            }

            /*
              Only pending orders
              should receive a new offer.
            */

            if (
                order.status !==
                "pending"
            ) {
                await connection.rollback();
                return;
            }

            /*
              Find drivers while the order
              is protected locally.
            */

            const eligible =
                await findEligibleDrivers(
                    order,
                    connection
                );

            if (
                eligible.length === 0
            ) {
                await connection.rollback();
                return;
            }

            const driver =
                eligible[0];

            /*
              Lock selected driver.
            */

            const [
                driverRows
            ] =
                await connection.execute(
                    `
                    SELECT *
                    FROM drivers
                    WHERE id = ?
                    AND is_online = 1
                    AND is_active = 1
                    FOR UPDATE
                    `,
                    [driver.id]
                );

            const lockedDriver =
                driverRows[0];

            if (!lockedDriver) {
                await connection.rollback();

                /*
                  Retry once through scanner.
                */
                return;
            }

            if (
                Number(
                    lockedDriver.current_orders_count
                ) >=
                Number(
                    lockedDriver.max_concurrent_orders
                )
            ) {
                await connection.rollback();
                return;
            }

            /*
              Re-check location freshness
              after locking driver.
            */

            if (
                !lockedDriver.last_location_update
            ) {
                await connection.rollback();
                return;
            }

            /*
              Create 20-second offer.
            */

            const expiresAt =
                new Date(
                    Date.now() +
                    OFFER_DURATION_MS
                );

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'offered',
                    offered_driver_id = ?,
                    offer_expires_at = ?
                WHERE id = ?
                AND status = 'pending'
                `,
                [
                    lockedDriver.id,
                    expiresAt,
                    id
                ]
            );

            await connection.execute(
                `
                INSERT INTO order_dispatch_log
                (
                    order_id,
                    driver_id,
                    status
                )
                VALUES (?, ?, 'offered')
                `,
                [
                    id,
                    lockedDriver.id
                ]
            );

            await addStatusHistory(
                connection,
                id,
                "pending",
                "offered",
                "system",
                null
            );

            await connection.commit();

            /*
              Send offer AFTER commit.
            */

            const offeredOrder =
                await getOrderById(
                    id
                );

            io.to(
                driverRoom(
                    lockedDriver.id
                )
            ).emit(
                "order:offer",
                offeredOrder
            );

            emitOrderUpdate(
                offeredOrder
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            throw error;
        } finally {
            connection.release();
        }
    } catch (error) {
        console.error(
            "Dispatch error:",
            error
        );
    } finally {
        dispatchLocks.delete(id);
    }
}

/* =========================================================
   EXPIRE ONE OFFER
========================================================= */

async function expireOffer(
    orderId
) {
    const connection =
        await pool.getConnection();

    let expiredDriverId =
        null;

    try {
        await connection.beginTransaction();

        const [rows] =
            await connection.execute(
                `
                SELECT *
                FROM orders
                WHERE id = ?
                FOR UPDATE
                `,
                [orderId]
            );

        const order =
            rows[0];

        if (
            !order ||
            order.status !== "offered"
        ) {
            await connection.rollback();
            return false;
        }

        if (
            !order.offer_expires_at ||
            new Date(
                order.offer_expires_at
            ) > new Date()
        ) {
            await connection.rollback();
            return false;
        }

        expiredDriverId =
            order.offered_driver_id;

        await connection.execute(
            `
            UPDATE order_dispatch_log
            SET status = 'expired'
            WHERE order_id = ?
            AND driver_id = ?
            AND status = 'offered'
            `,
            [
                order.id,
                order.offered_driver_id
            ]
        );

        /*
          Timeout counts as a missed offer,
          but we do NOT punish the driver
          automatically.
        */

        await connection.execute(
            `
            UPDATE orders
            SET
                status = 'pending',
                offered_driver_id = NULL,
                offer_expires_at = NULL
            WHERE id = ?
            `,
            [order.id]
        );

        await addStatusHistory(
            connection,
            order.id,
            "offered",
            "pending",
            "system",
            null
        );

        await connection.commit();

        const updated =
            await getOrderById(
                order.id
            );

        emitOrderUpdate(
            updated
        );

        return true;
    } catch (error) {
        try {
            await connection.rollback();
        } catch (_) {}

        console.error(
            "Offer expiration error:",
            error
        );

        return false;
    } finally {
        connection.release();
    }
}

/* =========================================================
   DRIVER ACCEPT ORDER
========================================================= */

app.post(
    "/api/orders/:id/accept",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();
                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                order.status !==
                "offered"
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "This order is no longer available."
                );
            }

            if (
                Number(
                    order.offered_driver_id
                ) !==
                Number(
                    req.user.id
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    403,
                    "This order was not offered to you."
                );
            }

            if (
                order.offer_expires_at &&
                new Date(
                    order.offer_expires_at
                ) <= new Date()
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "The offer has expired."
                );
            }

            const [
                drivers
            ] =
                await connection.execute(
                    `
                    SELECT *
                    FROM drivers
                    WHERE id = ?
                    AND is_active = 1
                    AND is_online = 1
                    FOR UPDATE
                    `,
                    [req.user.id]
                );

            const driver =
                drivers[0];

            if (!driver) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Driver not found."
                );
            }

            if (
                Number(
                    driver.current_orders_count
                ) >=
                Number(
                    driver.max_concurrent_orders
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Driver has reached the maximum number of orders."
                );
            }

            /*
              SECOND ORDER VALIDATION
            */

            if (
                Number(
                    driver.current_orders_count
                ) >= 1
            ) {
                if (
                    Number(
                        driver.max_concurrent_orders
                    ) < 2
                ) {
                    await connection.rollback();

                    return sendError(
                        res,
                        409,
                        "Driver cannot carry a second order."
                    );
                }

                const [
                    activeOrders
                ] =
                    await connection.execute(
                        `
                        SELECT
                            id,
                            delivery_lat,
                            delivery_lng
                        FROM orders
                        WHERE driver_id = ?
                        AND status IN
                        (
                            'accepted',
                            'picking_up',
                            'delivering'
                        )
                        FOR UPDATE
                        `,
                        [driver.id]
                    );

                let validSecondOrder =
                    false;

                for (
                    const active
                    of activeOrders
                ) {
                    if (
                        !isValidCoordinate(
                            active.delivery_lat,
                            active.delivery_lng
                        )
                    ) {
                        continue;
                    }

                    const distance =
                        calculateDistance(
                            active.delivery_lat,
                            active.delivery_lng,
                            order.delivery_lat,
                            order.delivery_lng
                        );

                    if (
                        distance <=
                        SECOND_ORDER_MAX_DISTANCE_KM
                    ) {
                        validSecondOrder =
                            true;
                        break;
                    }
                }

                if (
                    !validSecondOrder
                ) {
                    await connection.rollback();

                    return sendError(
                        res,
                        409,
                        "The second order is too far from the existing delivery."
                    );
                }
            }

            /*
              Accept atomically.
            */

            const [
                updateResult
            ] =
                await connection.execute(
                    `
                    UPDATE orders
                    SET
                        driver_id = ?,
                        offered_driver_id = NULL,
                        status = 'accepted',
                        accepted_at = NOW(),
                        offer_expires_at = NULL
                    WHERE id = ?
                    AND status = 'offered'
                    AND offered_driver_id = ?
                    `,
                    [
                        driver.id,
                        orderId,
                        driver.id
                    ]
                );

            if (
                updateResult.affectedRows !== 1
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Order was already taken."
                );
            }

            await connection.execute(
                `
                UPDATE order_dispatch_log
                SET status = 'accepted'
                WHERE order_id = ?
                AND driver_id = ?
                AND status = 'offered'
                `,
                [
                    orderId,
                    driver.id
                ]
            );

            await connection.execute(
                `
                UPDATE drivers
                SET current_orders_count =
                    current_orders_count + 1
                WHERE id = ?
                AND current_orders_count <
                    max_concurrent_orders
                `,
                [driver.id]
            );

            await addStatusHistory(
                connection,
                orderId,
                "offered",
                "accepted",
                "driver",
                driver.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            io.to(
                driverRoom(
                    driver.id
                )
            ).emit(
                "order:accepted",
                updated
            );

            const freshDriver =
                await getDriverById(
                    driver.id
                );

            emitDriverUpdate(
                freshDriver
            );

            return sendSuccess(
                res,
                {
                    message:
                        "Order accepted.",
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(
                "Accept error:",
                error
            );

            return sendError(
                res,
                500,
                "Could not accept order."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   DRIVER REJECT ORDER
========================================================= */

app.post(
    "/api/orders/:id/reject",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                order.status !==
                    "offered" ||
                Number(
                    order.offered_driver_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "This order is not currently offered to you."
                );
            }

            if (
                order.offer_expires_at &&
                new Date(
                    order.offer_expires_at
                ) <= new Date()
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "The offer has expired."
                );
            }

            await connection.execute(
                `
                UPDATE order_dispatch_log
                SET status = 'rejected'
                WHERE order_id = ?
                AND driver_id = ?
                AND status = 'offered'
                `,
                [
                    orderId,
                    req.user.id
                ]
            );

            /*
              Rejection = -1 point.
              Never below zero.
            */

            await connection.execute(
                `
                UPDATE drivers
                SET driver_points =
                    GREATEST(
                        driver_points - 1,
                        0
                    )
                WHERE id = ?
                `,
                [req.user.id]
            );

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'pending',
                    offered_driver_id = NULL,
                    offer_expires_at = NULL
                WHERE id = ?
                `,
                [orderId]
            );

            await addStatusHistory(
                connection,
                orderId,
                "offered",
                "pending",
                "driver",
                req.user.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            const driver =
                await getDriverById(
                    req.user.id
                );

            emitDriverUpdate(
                driver
            );

            processOrderDispatch(
                orderId
            ).catch(console.error);

            return sendSuccess(
                res,
                {
                    message:
                        "Order rejected.",
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(
                "Reject error:",
                error
            );

            return sendError(
                res,
                500,
                "Could not reject order."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   VERIFY OTP AT RESTAURANT
========================================================= */

app.post(
    "/api/orders/:id/verify-pickup",
    authenticate,
    requireRole("restaurant"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            const {
                otp_code
            } = req.body;

            if (
                !otp_code ||
                !/^\d{4}$/.test(
                    String(otp_code)
                )
            ) {
                return sendError(
                    res,
                    400,
                    "OTP must contain exactly 4 digits."
                );
            }

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                Number(
                    order.restaurant_id
                ) !==
                Number(
                    req.user.id
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            if (
                order.status !==
                "accepted"
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Order is not ready for pickup verification."
                );
            }

            if (
                String(order.otp_code) !==
                String(otp_code)
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    400,
                    "Incorrect OTP."
                );
            }

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'picking_up',
                    restaurant_paid_at = NOW(),
                    pickup_verified_at = NOW(),
                    payment_status = 'paid'
                WHERE id = ?
                AND status = 'accepted'
                `,
                [orderId]
            );

            /*
              Prevent duplicate platform fee.
            */

            if (
                Number(
                    order.platform_fee_recorded
                ) === 0
            ) {
                await connection.execute(
                    `
                    UPDATE restaurants
                    SET balance_due =
                        balance_due +
                        ?
                    WHERE id = ?
                    `,
                    [
                        Number(
                            order.platform_fee
                        ),
                        order.restaurant_id
                    ]
                );

                await connection.execute(
                    `
                    INSERT INTO restaurant_transactions
                    (
                        restaurant_id,
                        order_id,
                        amount,
                        type,
                        note
                    )
                    VALUES (?, ?, ?, 'platform_fee', ?)
                    `,
                    [
                        order.restaurant_id,
                        orderId,
                        Number(
                            order.platform_fee
                        ),
                        "Platform delivery fee"
                    ]
                );

                await connection.execute(
                    `
                    UPDATE orders
                    SET platform_fee_recorded = 1
                    WHERE id = ?
                    `,
                    [orderId]
                );
            }

            await addStatusHistory(
                connection,
                orderId,
                "accepted",
                "picking_up",
                "restaurant",
                req.user.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            return sendSuccess(
                res,
                {
                    message:
                        "Pickup verified successfully.",
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not verify pickup."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   DRIVER START DELIVERY
========================================================= */

app.post(
    "/api/orders/:id/start-delivery",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                Number(
                    order.driver_id
                ) !==
                Number(
                    req.user.id
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    403,
                    "This order does not belong to you."
                );
            }

            if (
                order.status !==
                "picking_up"
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Order is not ready for delivery."
                );
            }

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'delivering',
                    delivery_started_at = NOW()
                WHERE id = ?
                AND status = 'picking_up'
                `,
                [orderId]
            );

            await addStatusHistory(
                connection,
                orderId,
                "picking_up",
                "delivering",
                "driver",
                req.user.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            return sendSuccess(
                res,
                {
                    message:
                        "Delivery started.",
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not start delivery."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   COMPLETE DELIVERY
========================================================= */

app.post(
    "/api/orders/:id/complete",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                Number(
                    order.driver_id
                ) !==
                Number(
                    req.user.id
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    403,
                    "This order does not belong to you."
                );
            }

            if (
                order.status !==
                "delivering"
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Order is not currently being delivered."
                );
            }

            const driverEarning =
                Number(
                    order.delivery_fee
                );

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'completed',
                    completed_at = NOW()
                WHERE id = ?
                AND status = 'delivering'
                `,
                [orderId]
            );

            await connection.execute(
                `
                UPDATE drivers
                SET
                    current_orders_count =
                        GREATEST(
                            current_orders_count - 1,
                            0
                        ),

                    wallet_balance =
                        wallet_balance + ?,

                    total_earnings =
                        total_earnings + ?
                WHERE id = ?
                `,
                [
                    driverEarning,
                    driverEarning,
                    req.user.id
                ]
            );

            if (
                driverEarning > 0
            ) {
                await connection.execute(
                    `
                    INSERT INTO driver_transactions
                    (
                        driver_id,
                        order_id,
                        amount,
                        type,
                        note
                    )
                    VALUES (?, ?, ?, 'delivery_earning', ?)
                    `,
                    [
                        req.user.id,
                        orderId,
                        driverEarning,
                        "Delivery earning"
                    ]
                );
            }

            await addStatusHistory(
                connection,
                orderId,
                "delivering",
                "completed",
                "driver",
                req.user.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            const driver =
                await getDriverById(
                    req.user.id
                );

            emitDriverUpdate(
                driver
            );

            return sendSuccess(
                res,
                {
                    message:
                        "Order completed.",
                    earning:
                        driverEarning,
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not complete order."
            );
        } finally {
            connection.release();
        }
    }
);
/* =========================================================
   CANCEL ORDER
========================================================= */

app.post(
    "/api/orders/:id/cancel",
    authenticate,
    requireRole(
        "restaurant",
        "admin"
    ),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const orderId =
                Number(req.params.id);

            const reason =
                String(
                    req.body.reason ||
                    "Cancelled"
                ).slice(0, 500);

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [orderId]
                );

            const order =
                orders[0];

            if (!order) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                req.user.role ===
                    "restaurant" &&
                Number(
                    order.restaurant_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            if (
                [
                    "completed",
                    "cancelled"
                ].includes(
                    order.status
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    409,
                    "Order cannot be cancelled."
                );
            }

            await connection.execute(
                `
                UPDATE orders
                SET
                    status = 'cancelled',
                    cancelled_at = NOW(),
                    cancellation_reason = ?,
                    offered_driver_id = NULL,
                    offer_expires_at = NULL
                WHERE id = ?
                `,
                [
                    reason,
                    orderId
                ]
            );

            /*
              Release driver's active slot
              only if an actual driver owns
              the order.
            */

            if (
                order.driver_id
            ) {
                await connection.execute(
                    `
                    UPDATE drivers
                    SET current_orders_count =
                        GREATEST(
                            current_orders_count - 1,
                            0
                        )
                    WHERE id = ?
                    `,
                    [
                        order.driver_id
                    ]
                );
            }

            /*
              Refund platform fee exactly once.
            */

            if (
                Number(
                    order.platform_fee_recorded
                ) === 1
            ) {
                const fee =
                    Number(
                        order.platform_fee
                    );

                await connection.execute(
                    `
                    UPDATE restaurants
                    SET balance_due =
                        GREATEST(
                            balance_due - ?,
                            0
                        )
                    WHERE id = ?
                    `,
                    [
                        fee,
                        order.restaurant_id
                    ]
                );

                await connection.execute(
                    `
                    INSERT INTO restaurant_transactions
                    (
                        restaurant_id,
                        order_id,
                        amount,
                        type,
                        note
                    )
                    VALUES (?, ?, ?, 'adjustment', ?)
                    `,
                    [
                        order.restaurant_id,
                        orderId,
                        -fee,
                        "Refund of platform fee after cancellation"
                    ]
                );

                await connection.execute(
                    `
                    UPDATE orders
                    SET platform_fee_recorded = 0
                    WHERE id = ?
                    `,
                    [orderId]
                );
            }

            await addStatusHistory(
                connection,
                orderId,
                order.status,
                "cancelled",
                req.user.role,
                req.user.id
            );

            await connection.commit();

            const updated =
                await getOrderById(
                    orderId
                );

            emitOrderUpdate(
                updated
            );

            if (
                order.driver_id
            ) {
                const driver =
                    await getDriverById(
                        order.driver_id
                    );

                emitDriverUpdate(
                    driver
                );
            }

            return sendSuccess(
                res,
                {
                    message:
                        "Order cancelled.",
                    order: updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not cancel order."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   GET ORDER
========================================================= */

app.get(
    "/api/orders/:id",
    authenticate,
    async (req, res) => {
        try {
            const orderId =
                Number(req.params.id);

            const order =
                await getOrderById(
                    orderId
                );

            if (!order) {
                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                req.user.role ===
                    "restaurant" &&
                Number(
                    order.restaurant_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            if (
                req.user.role ===
                    "driver" &&
                Number(
                    order.driver_id
                ) !==
                    Number(
                        req.user.id
                    ) &&
                Number(
                    order.offered_driver_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            return sendSuccess(
                res,
                {
                    order
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get order."
            );
        }
    }
);

/* =========================================================
   RESTAURANT ORDERS
========================================================= */

app.get(
    "/api/restaurant/orders",
    authenticate,
    requireRole("restaurant"),
    async (req, res) => {
        try {
            const limit =
                Math.min(
                    Math.max(
                        Number(
                            req.query.limit ||
                            100
                        ),
                        1
                    ),
                    500
                );

            const [
                orders
            ] =
                await pool.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE restaurant_id = ?
                    ORDER BY created_at DESC
                    LIMIT ${limit}
                    `,
                    [req.user.id]
                );

            return sendSuccess(
                res,
                {
                    orders
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get restaurant orders."
            );
        }
    }
);

/* =========================================================
   DRIVER ORDERS
========================================================= */

app.get(
    "/api/driver/orders",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            const [
                orders
            ] =
                await pool.execute(
                    `
                    SELECT *
                    FROM orders
                    WHERE
                        driver_id = ?
                        OR offered_driver_id = ?
                    ORDER BY created_at DESC
                    LIMIT 500
                    `,
                    [
                        req.user.id,
                        req.user.id
                    ]
                );

            return sendSuccess(
                res,
                {
                    orders
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get driver orders."
            );
        }
    }
);

/* =========================================================
   ADMIN ORDERS
========================================================= */

app.get(
    "/api/admin/orders",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const [
                orders
            ] =
                await pool.execute(
                    `
                    SELECT
                        o.*,
                        r.name AS restaurant_name,
                        r.phone AS restaurant_phone,
                        d.name AS driver_name,
                        d.phone AS driver_phone
                    FROM orders o
                    JOIN restaurants r
                        ON r.id = o.restaurant_id
                    LEFT JOIN drivers d
                        ON d.id = o.driver_id
                    ORDER BY
                        o.created_at DESC
                    LIMIT 1000
                    `
                );

            return sendSuccess(
                res,
                {
                    orders
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get orders."
            );
        }
    }
);

/* =========================================================
   ORDER HISTORY
========================================================= */

app.get(
    "/api/orders/:id/history",
    authenticate,
    async (req, res) => {
        try {
            const orderId =
                Number(req.params.id);

            const order =
                await getOrderById(
                    orderId
                );

            if (!order) {
                return sendError(
                    res,
                    404,
                    "Order not found."
                );
            }

            if (
                req.user.role ===
                    "restaurant" &&
                Number(
                    order.restaurant_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            if (
                req.user.role ===
                    "driver" &&
                Number(
                    order.driver_id
                ) !==
                    Number(
                        req.user.id
                    ) &&
                Number(
                    order.offered_driver_id
                ) !==
                    Number(
                        req.user.id
                    )
            ) {
                return sendError(
                    res,
                    403,
                    "Access denied."
                );
            }

            const [
                history
            ] =
                await pool.execute(
                    `
                    SELECT *
                    FROM order_status_history
                    WHERE order_id = ?
                    ORDER BY created_at ASC
                    `,
                    [orderId]
                );

            return sendSuccess(
                res,
                {
                    history
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get order history."
            );
        }
    }
);

/* =========================================================
   RESTAURANT DASHBOARD
========================================================= */

app.get(
    "/api/restaurant/dashboard",
    authenticate,
    requireRole("restaurant"),
    async (req, res) => {
        try {
            const restaurantId =
                req.user.id;

            const [[today]] =
                await pool.execute(
                    `
                    SELECT
                        COUNT(*) AS orders_today,

                        COALESCE(
                            SUM(food_price),
                            0
                        ) AS food_total_today,

                        COALESCE(
                            SUM(delivery_fee),
                            0
                        ) AS delivery_total_today,

                        COALESCE(
                            SUM(platform_fee),
                            0
                        ) AS platform_fees_today

                    FROM orders
                    WHERE restaurant_id = ?

                    AND DATE(created_at) =
                        CURDATE()

                    AND status <>
                        'cancelled'
                    `,
                    [restaurantId]
                );

            const [[balance]] =
                await pool.execute(
                    `
                    SELECT
                        balance_due
                    FROM restaurants
                    WHERE id = ?
                    `,
                    [restaurantId]
                );

            const [[drivers]] =
                await pool.execute(
                    `
                    SELECT
                        COUNT(
                            DISTINCT driver_id
                        ) AS active_drivers
                    FROM orders
                    WHERE restaurant_id = ?
                    AND status IN
                    (
                        'accepted',
                        'picking_up',
                        'delivering'
                    )
                    AND driver_id IS NOT NULL
                    `,
                    [restaurantId]
                );

            return sendSuccess(
                res,
                {
                    orders_today:
                        Number(
                            today.orders_today
                        ),

                    food_total_today:
                        Number(
                            today.food_total_today
                        ),

                    delivery_total_today:
                        Number(
                            today.delivery_total_today
                        ),

                    platform_fees_today:
                        Number(
                            today.platform_fees_today
                        ),

                    balance_due:
                        Number(
                            balance?.balance_due ||
                            0
                        ),

                    active_drivers:
                        Number(
                            drivers.active_drivers
                        )
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get restaurant dashboard."
            );
        }
    }
);

/* =========================================================
   DRIVER DASHBOARD
========================================================= */

app.get(
    "/api/driver/dashboard",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            const driverId =
                req.user.id;

            const [[today]] =
                await pool.execute(
                    `
                    SELECT
                        COUNT(*) AS orders_today,

                        COALESCE(
                            SUM(delivery_fee),
                            0
                        ) AS earnings_today

                    FROM orders

                    WHERE driver_id = ?

                    AND DATE(completed_at) =
                        CURDATE()

                    AND status =
                        'completed'
                    `,
                    [driverId]
                );

            const [[driver]] =
                await pool.execute(
                    `
                    SELECT
                        current_orders_count,
                        max_concurrent_orders,
                        wallet_balance,
                        total_earnings,
                        driver_points,
                        is_online
                    FROM drivers
                    WHERE id = ?
                    `,
                    [driverId]
                );

            if (!driver) {
                return sendError(
                    res,
                    404,
                    "Driver not found."
                );
            }

            return sendSuccess(
                res,
                {
                    orders_today:
                        Number(
                            today.orders_today
                        ),

                    earnings_today:
                        Number(
                            today.earnings_today
                        ),

                    current_orders_count:
                        Number(
                            driver.current_orders_count
                        ),

                    max_concurrent_orders:
                        Number(
                            driver.max_concurrent_orders
                        ),

                    wallet_balance:
                        Number(
                            driver.wallet_balance
                        ),

                    total_earnings:
                        Number(
                            driver.total_earnings
                        ),

                    driver_points:
                        Number(
                            driver.driver_points
                        ),

                    is_online:
                        Boolean(
                            driver.is_online
                        )
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get driver dashboard."
            );
        }
    }
);

/* =========================================================
   ADMIN DASHBOARD
========================================================= */

app.get(
    "/api/admin/dashboard",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const [[stats]] =
                await pool.execute(
                    `
                    SELECT

                    (
                        SELECT COUNT(*)
                        FROM restaurants
                        WHERE is_active = 1
                    ) AS restaurants_count,

                    (
                        SELECT COUNT(*)
                        FROM drivers
                        WHERE is_active = 1
                    ) AS drivers_count,

                    (
                        SELECT COUNT(*)
                        FROM drivers
                        WHERE
                            is_active = 1
                            AND is_online = 1
                    ) AS online_drivers,

                    (
                        SELECT COUNT(*)
                        FROM orders
                        WHERE
                            DATE(created_at) =
                            CURDATE()
                    ) AS orders_today,

                    (
                        SELECT COALESCE(
                            SUM(platform_fee),
                            0
                        )
                        FROM orders
                        WHERE
                            DATE(created_at) =
                            CURDATE()
                            AND status <>
                            'cancelled'
                    ) AS revenue_today,

                    (
                        SELECT COALESCE(
                            SUM(
                                CASE
                                    WHEN type =
                                        'platform_fee'
                                    THEN amount
                                    WHEN type =
                                        'adjustment'
                                    THEN amount
                                    ELSE 0
                                END
                            ),
                            0
                        )
                        FROM restaurant_transactions
                    ) AS revenue_total
                    `
                );

            const [[balances]] =
                await pool.execute(
                    `
                    SELECT
                        COALESCE(
                            SUM(balance_due),
                            0
                        ) AS restaurants_balance_due
                    FROM restaurants
                    WHERE is_active = 1
                    `
                );

            return sendSuccess(
                res,
                {
                    restaurants_count:
                        Number(
                            stats.restaurants_count
                        ),

                    drivers_count:
                        Number(
                            stats.drivers_count
                        ),

                    online_drivers:
                        Number(
                            stats.online_drivers
                        ),

                    orders_today:
                        Number(
                            stats.orders_today
                        ),

                    revenue_today:
                        Number(
                            stats.revenue_today
                        ),

                    revenue_total:
                        Number(
                            stats.revenue_total
                        ),

                    restaurants_balance_due:
                        Number(
                            balances.restaurants_balance_due
                        )
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get admin dashboard."
            );
        }
    }
);

/* =========================================================
   ADMIN - ALL RESTAURANTS
========================================================= */

app.get(
    "/api/admin/restaurants",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const [
                restaurants
            ] =
                await pool.execute(
                    `
                    SELECT
                        id,
                        name,
                        phone,
                        address,
                        lat,
                        lng,
                        balance_due,
                        is_active,
                        created_at,
                        updated_at
                    FROM restaurants
                    ORDER BY created_at DESC
                    `
                );

            return sendSuccess(
                res,
                {
                    restaurants
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get restaurants."
            );
        }
    }
);

/* =========================================================
   ADMIN - ALL DRIVERS
========================================================= */

app.get(
    "/api/admin/drivers",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        try {
            const [
                drivers
            ] =
                await pool.execute(
                    `
                    SELECT
                        id,
                        name,
                        phone,
                        vehicle,
                        lat,
                        lng,
                        last_location_update,
                        is_online,
                        is_active,
                        current_orders_count,
                        max_concurrent_orders,
                        radius,
                        driver_points,
                        wallet_balance,
                        total_earnings,
                        created_at,
                        updated_at
                    FROM drivers
                    ORDER BY created_at DESC
                    `
                );

            return sendSuccess(
                res,
                {
                    drivers
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get drivers."
            );
        }
    }
);

/* =========================================================
   ADMIN - RESTAURANT PAYMENT
========================================================= */

app.post(
    "/api/admin/restaurants/:id/payment",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const restaurantId =
                Number(req.params.id);

            const amount =
                Number(
                    req.body.amount
                );

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid payment amount."
                );
            }

            await connection.beginTransaction();

            const [rows] =
                await connection.execute(
                    `
                    SELECT *
                    FROM restaurants
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [restaurantId]
                );

            const restaurant =
                rows[0];

            if (!restaurant) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Restaurant not found."
                );
            }

            if (
                amount >
                Number(
                    restaurant.balance_due
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    400,
                    "Payment exceeds restaurant balance."
                );
            }

            await connection.execute(
                `
                UPDATE restaurants
                SET balance_due =
                    balance_due - ?
                WHERE id = ?
                `,
                [
                    amount,
                    restaurantId
                ]
            );

            await connection.execute(
                `
                INSERT INTO restaurant_transactions
                (
                    restaurant_id,
                    order_id,
                    amount,
                    type,
                    note
                )
                VALUES (?, NULL, ?, 'payment', ?)
                `,
                [
                    restaurantId,
                    -amount,
                    "Restaurant payment received"
                ]
            );

            await connection.commit();

            const updated =
                await getRestaurantById(
                    restaurantId
                );

            return sendSuccess(
                res,
                {
                    message:
                        "Payment recorded.",
                    restaurant:
                        updated
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not record payment."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
    "/api/restaurant/transactions",
    authenticate,
    requireRole("restaurant"),
    async (req, res) => {
        try {
            const [
                transactions
            ] =
                await pool.execute(
                    `
                    SELECT *
                    FROM restaurant_transactions
                    WHERE restaurant_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1000
                    `,
                    [req.user.id]
                );

            return sendSuccess(
                res,
                {
                    transactions
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get transactions."
            );
        }
    }
);

app.get(
    "/api/driver/transactions",
    authenticate,
    requireRole("driver"),
    async (req, res) => {
        try {
            const [
                transactions
            ] =
                await pool.execute(
                    `
                    SELECT *
                    FROM driver_transactions
                    WHERE driver_id = ?
                    ORDER BY created_at DESC
                    LIMIT 1000
                    `,
                    [req.user.id]
                );

            return sendSuccess(
                res,
                {
                    transactions
                }
            );
        } catch (error) {
            console.error(error);

            return sendError(
                res,
                500,
                "Could not get transactions."
            );
        }
    }
);

/* =========================================================
   ADMIN DRIVER WITHDRAWAL
========================================================= */

app.post(
    "/api/admin/drivers/:id/withdrawal",
    authenticate,
    requireRole("admin"),
    async (req, res) => {
        const connection =
            await pool.getConnection();

        try {
            const driverId =
                Number(req.params.id);

            const amount =
                Number(
                    req.body.amount
                );

            if (
                !Number.isFinite(amount) ||
                amount <= 0
            ) {
                return sendError(
                    res,
                    400,
                    "Invalid withdrawal amount."
                );
            }

            await connection.beginTransaction();

            const [rows] =
                await connection.execute(
                    `
                    SELECT *
                    FROM drivers
                    WHERE id = ?
                    FOR UPDATE
                    `,
                    [driverId]
                );

            const driver =
                rows[0];

            if (!driver) {
                await connection.rollback();

                return sendError(
                    res,
                    404,
                    "Driver not found."
                );
            }

            if (
                amount >
                Number(
                    driver.wallet_balance
                )
            ) {
                await connection.rollback();

                return sendError(
                    res,
                    400,
                    "Withdrawal exceeds driver balance."
                );
            }

            await connection.execute(
                `
                UPDATE drivers
                SET wallet_balance =
                    wallet_balance - ?
                WHERE id = ?
                `,
                [
                    amount,
                    driverId
                ]
            );

            await connection.execute(
                `
                INSERT INTO driver_transactions
                (
                    driver_id,
                    order_id,
                    amount,
                    type,
                    note
                )
                VALUES (?, NULL, ?, 'withdrawal', ?)
                `,
                [
                    driverId,
                    -amount,
                    "Driver withdrawal"
                ]
            );

            await connection.commit();

            return sendSuccess(
                res,
                {
                    message:
                        "Withdrawal recorded."
                }
            );
        } catch (error) {
            try {
                await connection.rollback();
            } catch (_) {}

            console.error(error);

            return sendError(
                res,
                500,
                "Could not record withdrawal."
            );
        } finally {
            connection.release();
        }
    }
);

/* =========================================================
   SOCKET.IO AUTHENTICATION
========================================================= */

io.use(
    (socket, next) => {
        try {
            const token =
                socket.handshake.auth?.token ||
                socket.handshake
                    .headers
                    ?.authorization
                    ?.replace(
                        "Bearer ",
                        ""
                    );

            if (!token) {
                return next(
                    new Error(
                        "Authentication required."
                    )
                );
            }

            const decoded =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            socket.user =
                decoded;

            next();
        } catch (_) {
            next(
                new Error(
                    "Invalid token."
                )
            );
        }
    }
);

/* =========================================================
   SOCKET.IO CONNECTION
========================================================= */

io.on(
    "connection",
    socket => {
        const user =
            socket.user;

        console.log(
            `Socket connected: ${user.role}:${user.id}`
        );

        if (
            user.role ===
            "driver"
        ) {
            socket.join(
                driverRoom(
                    user.id
                )
            );
        }

        if (
            user.role ===
            "restaurant"
        ) {
            socket.join(
                restaurantRoom(
                    user.id
                )
            );
        }

        if (
            user.role ===
            "admin"
        ) {
            socket.join(
                adminRoom()
            );
        }

        socket.on(
            "driver:location",
            async data => {
                try {
                    if (
                        user.role !==
                        "driver"
                    ) {
                        return;
                    }

                    const {
                        lat,
                        lng
                    } = data || {};

                    if (
                        !isValidCoordinate(
                            lat,
                            lng
                        )
                    ) {
                        return;
                    }

                    const updated =
                        await updateDriverLocation(
                            user.id,
                            lat,
                            lng
                        );

                    if (!updated) {
                        return;
                    }

                    await broadcastDriverLocation(
                        user.id,
                        lat,
                        lng
                    );
                } catch (error) {
                    console.error(
                        "Socket location error:",
                        error
                    );
                }
            }
        );

        socket.on(
            "disconnect",
            () => {
                console.log(
                    `Socket disconnected: ${user.role}:${user.id}`
                );
            }
        );
    }
);

/* =========================================================
   AUTOMATIC DISPATCH SCANNER
========================================================= */

setInterval(
    async () => {
        try {
            /*
              First expire old offers.
            */

            const [
                expiredOrders
            ] =
                await pool.execute(
                    `
                    SELECT id
                    FROM orders
                    WHERE
                        status = 'offered'
                        AND offer_expires_at
                            IS NOT NULL
                        AND offer_expires_at
                            <= NOW()
                    ORDER BY created_at ASC
                    LIMIT 50
                    `
                );

            for (
                const order
                of expiredOrders
            ) {
                await expireOffer(
                    order.id
                );
            }

            /*
              Then dispatch pending orders.
            */

            const [
                pendingOrders
            ] =
                await pool.execute(
                    `
                    SELECT id
                    FROM orders
                    WHERE status = 'pending'
                    ORDER BY created_at ASC
                    LIMIT 50
                    `
                );

            for (
                const order
                of pendingOrders
            ) {
                processOrderDispatch(
                    order.id
                ).catch(
                    console.error
                );
            }
        } catch (error) {
            console.error(
                "Dispatch scanner error:",
                error
            );
        }
    },
    5000
);

/* =========================================================
   GLOBAL ERROR HANDLER
========================================================= */

app.use(
    (err, req, res, next) => {
        console.error(err);

        if (
            res.headersSent
        ) {
            return next(err);
        }

        return res
            .status(500)
            .json({
                success: false,
                message:
                    "Internal server error."
            });
    }
);

/* =========================================================
   404
========================================================= */

app.use(
    (req, res) => {
        res.status(404).json({
            success: false,
            message:
                "Route not found."
        });
    }
);

/* =========================================================
   GRACEFUL SHUTDOWN
========================================================= */

let shuttingDown = false;

async function shutdown(
    signal
) {
    if (shuttingDown) {
        return;
    }

    shuttingDown = true;

    console.log(
        `${signal}: shutting down...`
    );

    server.close(
        async () => {
            try {
                await pool.end();

                console.log(
                    "MySQL pool closed."
                );

                process.exit(0);
            } catch (error) {
                console.error(
                    "Shutdown error:",
                    error
                );

                process.exit(1);
            }
        }
    );

    setTimeout(
        () => {
            console.error(
                "Forced shutdown."
            );

            process.exit(1);
        },
        10000
    ).unref();
}

process.on(
    "SIGINT",
    () => shutdown("SIGINT")
);

process.on(
    "SIGTERM",
    () => shutdown("SIGTERM")
);

/* =========================================================
   START SERVER
========================================================= */

async function startServer() {
    try {
        await pool.query(
            "SELECT 1"
        );

        console.log(
            "MySQL database connected successfully."
        );

        server.listen(
            PORT,
            "0.0.0.0",
            () => {
                console.log(
                    "======================================"
                );

                console.log(
                    "      HADROUG DELIVERY SERVER"
                );

                console.log(
                    "======================================"
                );

                console.log(
                    `Server running on port ${PORT}`
                );

                console.log(
                    `http://localhost:${PORT}`
                );

                console.log(
                    "Socket.IO: ENABLED"
                );

                console.log(
                    "Dispatch engine: ENABLED"
                );

                console.log(
                    "Two-order system: ENABLED"
                );

                console.log(
                    "Offer duration: 20 seconds"
                );

                console.log(
                    "Driver location timeout: 60 seconds"
                );
            }
        );
    } catch (error) {
        console.error(
            "Could not start server."
        );

        console.error(error);

        process.exit(1);
    }
}

startServer();
