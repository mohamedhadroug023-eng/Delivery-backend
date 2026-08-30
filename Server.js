require("dotenv").config();

const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const mysql = require("mysql2/promise");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);

/* =====================================================
   CONFIG
===================================================== */

const PORT = Number(process.env.PORT || 3000);

const JWT_SECRET = process.env.JWT_SECRET;

const OFFER_SECONDS = 20;

// المسافة القصوى العادية بين السائق والمطعم
const DEFAULT_RADIUS_KM = 2.5;

// أقصى مسافة بين الزبون الأول والثاني
// للسماح للسائق بأخذ طلبين
const SECOND_ORDER_MAX_DISTANCE_KM = 2.0;

// عمولتك من المطعم
const PLATFORM_FEE = 1.000;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
    throw new Error(
        "JWT_SECRET must exist in .env and contain at least 32 characters."
    );
}

/* =====================================================
   CORS
===================================================== */

const CORS_ORIGINS = process.env.CORS_ORIGIN
    ? process.env.CORS_ORIGIN
        .split(",")
        .map(x => x.trim())
        .filter(Boolean)
    : true;

/* =====================================================
   SOCKET.IO
===================================================== */

const io = new Server(server, {
    cors: {
        origin: CORS_ORIGINS,
        methods: ["GET", "POST", "PATCH"],
        credentials: true
    }
});

const connectedDrivers = new Map();
const connectedRestaurants = new Map();
const connectedAdmins = new Set();

/* =====================================================
   MIDDLEWARE
===================================================== */

app.use(helmet());

app.use(cors({
    origin: CORS_ORIGINS,
    credentials: true
}));

app.use(express.json({
    limit: "100kb"
}));

const apiLimiter = rateLimit({
    windowMs: 60 * 1000,
    max: 120,
    standardHeaders: true,
    legacyHeaders: false
});

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    standardHeaders: true,
    legacyHeaders: false
});

app.use("/api/", apiLimiter);

/* =====================================================
   DATABASE
===================================================== */

const db = mysql.createPool({
    host: process.env.DB_HOST || "localhost",
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD || "",
    database: process.env.DB_NAME || "HADROUG_DELIVERY",

    waitForConnections: true,

    connectionLimit:
        Number(process.env.DB_CONNECTION_LIMIT || 10),

    queueLimit: 0,

    decimalNumbers: true
});

/* =====================================================
   HELPERS
===================================================== */

function cleanString(value, maxLength = 255) {

    if (typeof value !== "string") {
        return null;
    }

    const result = value.trim();

    if (!result || result.length > maxLength) {
        return null;
    }

    return result;
}

function normalizePhone(phone) {

    if (typeof phone !== "string") {
        return null;
    }

    const value = phone.trim();

    if (!/^[0-9+\-\s]{6,30}$/.test(value)) {
        return null;
    }

    return value;
}

function validCoordinates(lat, lng) {

    const a = Number(lat);
    const b = Number(lng);

    return (
        Number.isFinite(a) &&
        Number.isFinite(b) &&
        a >= -90 &&
        a <= 90 &&
        b >= -180 &&
        b <= 180
    );
}

function validMoney(value) {

    const n = Number(value);

    return (
        Number.isFinite(n) &&
        n >= 0 &&
        n <= 100000
    );
}

function validId(value) {

    const n = Number(value);

    return Number.isInteger(n) && n > 0;
}

/*
   كود 4 أرقام
*/
function generateOTP() {

    return String(
        crypto.randomInt(1000, 10000)
    );
}

/*
   JWT
*/
function generateToken(id, role) {

    return jwt.sign(
        {
            id: Number(id),
            role
        },
        JWT_SECRET,
        {
            expiresIn: "7d"
        }
    );
}

/*
   حساب المسافة بالكيلومتر
   Haversine
*/
function calculateDistance(
    lat1,
    lng1,
    lat2,
    lng2
) {

    const R = 6371;

    const dLat =
        ((lat2 - lat1) * Math.PI) / 180;

    const dLng =
        ((lng2 - lng1) * Math.PI) / 180;

    const a =
        Math.sin(dLat / 2) ** 2 +
        Math.cos((lat1 * Math.PI) / 180) *
        Math.cos((lat2 * Math.PI) / 180) *
        Math.sin(dLng / 2) ** 2;

    return (
        R *
        2 *
        Math.atan2(
            Math.sqrt(a),
            Math.sqrt(1 - a)
        )
    );
}

/* =====================================================
   AUTHENTICATION
===================================================== */

function authenticate(...allowedRoles) {

    return (req, res, next) => {

        try {

            const header =
                req.headers.authorization;

            if (
                !header ||
                !header.startsWith("Bearer ")
            ) {

                return res.status(401).json({
                    success: false,
                    message: "Authentication required."
                });
            }

            const token =
                header.substring(7).trim();

            const decoded =
                jwt.verify(token, JWT_SECRET);

            if (
                allowedRoles.length &&
                !allowedRoles.includes(decoded.role)
            ) {

                return res.status(403).json({
                    success: false,
                    message: "Access denied."
                });
            }

            req.user = decoded;

            next();

        } catch {

            return res.status(401).json({
                success: false,
                message: "Invalid or expired token."
            });
        }
    };
}

/* =====================================================
   HISTORY
===================================================== */

async function addHistory(
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

/* =====================================================
   EXCLUDED DRIVERS
===================================================== */

async function getExcludedDrivers(
    connection,
    orderId
) {

    const [rows] =
        await connection.execute(
            `
            SELECT driver_id
            FROM order_dispatch_log
            WHERE order_id = ?
            AND status IN ('rejected', 'expired')
            `,
            [orderId]
        );

    return rows.map(
        row => Number(row.driver_id)
    );
}

/* =====================================================
   FIND BEST DRIVER
===================================================== */

/*
   هنا قلب النظام.

   الحالة 1:
   السائق ليس لديه أي طلب
   -> يمكنه أخذ الطلب.

   الحالة 2:
   السائق لديه طلب واحد
   -> يمكنه أخذ الطلب الثاني فقط إذا:
      - max_concurrent_orders >= 2
      - الطلب الحالي مازال نشطا
      - الزبون الجديد قريب من الزبون الأول
      - السائق قريب من المطعم الجديد
*/

async function findBestDriver(
    connection,
    order,
    excludedDrivers
) {

    const [drivers] =
        await connection.execute(
            `
            SELECT
                d.id,
                d.lat,
                d.lng,
                d.radius,
                d.driver_points,
                d.current_orders_count,
                d.max_concurrent_orders,

                o.id AS existing_order_id,
                o.delivery_lat AS existing_delivery_lat,
                o.delivery_lng AS existing_delivery_lng

            FROM drivers d

            LEFT JOIN orders o
                ON o.driver_id = d.id
                AND o.status IN
                (
                    'accepted',
                    'picking_up',
                    'delivering'
                )

            WHERE d.is_active = 1
            AND d.is_online = 1
            AND d.lat IS NOT NULL
            AND d.lng IS NOT NULL

            ORDER BY
                d.current_orders_count ASC,
                d.driver_points DESC
            `
        );

    const candidates = [];

    for (const driver of drivers) {

        const driverId =
            Number(driver.id);

        if (
            excludedDrivers.includes(
                driverId
            )
        ) {
            continue;
        }

        const currentOrders =
            Number(
                driver.current_orders_count
            ) || 0;

        const maxOrders =
            Number(
                driver.max_concurrent_orders
            ) || 1;

        const radius =
            Math.min(
                Number(driver.radius) ||
                DEFAULT_RADIUS_KM,
                DEFAULT_RADIUS_KM
            );

        const distanceToRestaurant =
            calculateDistance(
                Number(driver.lat),
                Number(driver.lng),

                Number(order.pickup_lat),
                Number(order.pickup_lng)
            );

        /*
           ================================
           السائق الحر
           ================================
        */

        if (currentOrders === 0) {

            if (
                distanceToRestaurant <=
                radius
            ) {

                candidates.push({
                    id: driverId,
                    distance:
                        distanceToRestaurant,
                    points:
                        Number(
                            driver.driver_points
                        ) || 0,
                    mode: "free"
                });
            }

            continue;
        }

        /*
           ================================
           السائق لديه طلب واحد
           ================================
        */

        if (
            currentOrders === 1 &&
            maxOrders >= 2 &&
            driver.existing_order_id &&
            driver.existing_delivery_lat != null &&
            driver.existing_delivery_lng != null
        ) {

            const distanceBetweenCustomers =
                calculateDistance(

                    Number(
                        driver.existing_delivery_lat
                    ),

                    Number(
                        driver.existing_delivery_lng
                    ),

                    Number(
                        order.delivery_lat
                    ),

                    Number(
                        order.delivery_lng
                    )
                );

            /*
               يجب أن يكون الزبون الثاني
               قريبًا من الأول.
            */

            if (
                distanceBetweenCustomers <=
                SECOND_ORDER_MAX_DISTANCE_KM &&

                distanceToRestaurant <=
                radius
            ) {

                candidates.push({

                    id: driverId,

                    distance:
                        distanceToRestaurant,

                    points:
                        Number(
                            driver.driver_points
                        ) || 0,

                    mode: "double",

                    distanceBetweenCustomers
                });
            }
        }
    }

    /*
       الأقرب أولاً
       وإذا تساوت المسافة:
       النقاط الأعلى أولاً
    */

    candidates.sort(
        (a, b) =>
            a.distance - b.distance ||
            b.points - a.points
    );

    return candidates;
}

/* =====================================================
   DISPATCH ORDER
===================================================== */

async function dispatchOrder(orderId) {

    const connection =
        await db.getConnection();

    try {

        await connection.beginTransaction();

        const [orders] =
            await connection.execute(
                `
                SELECT
                    o.*,
                    r.name AS restaurant_name,
                    r.is_active AS restaurant_active

                FROM orders o

                JOIN restaurants r
                    ON r.id = o.restaurant_id

                WHERE o.id = ?

                FOR UPDATE
                `,
                [orderId]
            );

        if (!orders.length) {

            await connection.rollback();
            return;
        }

        const order = orders[0];

        if (
            Number(
                order.restaurant_active
            ) !== 1
        ) {

            await connection.rollback();
            return;
        }

        /*
           إذا كان الطلب تم قبوله
           لا نرسله مرة أخرى.
        */

        if (
            !["pending", "offered"]
                .includes(order.status)
        ) {

            await connection.rollback();
            return;
        }

        /*
           إذا كان العرض الحالي مازال صالحا
           لا نرسل عرضا آخر.
        */

        if (
            order.status === "offered" &&
            order.offer_expires_at
        ) {

            const [valid] =
                await connection.execute(
                    `
                    SELECT id
                    FROM orders
                    WHERE id = ?
                    AND status = 'offered'
                    AND offer_expires_at > NOW()
                    `,
                    [orderId]
                );

            if (valid.length) {

                await connection.rollback();
                return;
            }
        }

        /*
           السائق السابق انتهى عرضه.
        */

        if (
            order.status === "offered" &&
            order.offered_driver_id
        ) {

            const oldDriver =
                Number(
                    order.offered_driver_id
                );

            await connection.execute(
                `
                UPDATE order_dispatch_log
                SET status = 'expired'
                WHERE order_id = ?
                AND driver_id = ?
                AND status = 'offered'
                `,
                [
                    orderId,
                    oldDriver
                ]
            );

            /*
               عدم الإجابة خلال 20 ثانية
               ينقص نقطة واحدة.
            */

            await connection.execute(
                `
                UPDATE drivers
                SET driver_points =
                    GREATEST(
                        0,
                        driver_points - 1
                    )
                WHERE id = ?
                `,
                [oldDriver]
            );

            io.to(
                `driver_${oldDriver}`
            ).emit(
                "offer_expired",
                {
                    order_id: orderId
                }
            );
        }

        /*
           السائقون الذين رفضوا
           أو انتهت مدة عرضهم
        */

        const excluded =
            await getExcludedDrivers(
                connection,
                orderId
            );

        const candidates =
            await findBestDriver(
                connection,
                order,
                excluded
            );

        let selected = null;

        /*
           إعادة فحص السائق داخل transaction
           لمنع race conditions.
        */

        for (
            const candidate of candidates
        ) {

            const [rows] =
                await connection.execute(
                    `
                    SELECT
                        id,
                        is_active,
                        is_online,
                        current_orders_count,
                        max_concurrent_orders

                    FROM drivers
                    WHERE id = ?

                    FOR UPDATE
                    `,
                    [candidate.id]
                );

            if (!rows.length) {
                continue;
            }

            const driver = rows[0];

            if (
                Number(driver.is_active) !== 1 ||
                Number(driver.is_online) !== 1
            ) {
                continue;
            }

            const current =
                Number(
                    driver.current_orders_count
                );

            const max =
                Number(
                    driver.max_concurrent_orders
                ) || 1;

            if (current >= max) {
                continue;
            }

            selected = candidate;
            break;
        }

        /*
           لا يوجد سائق حاليا
        */

        if (!selected) {

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

            await connection.commit();

            io.to(
                `restaurant_${order.restaurant_id}`
            ).emit(
                "order_waiting",
                {
                    order_id: orderId
                }
            );

            return;
        }

        /*
           إنشاء العرض
           لمدة 20 ثانية
        */

        await connection.execute(
            `
            UPDATE orders

            SET
                status = 'offered',
                offered_driver_id = ?,
                offer_expires_at =
                    DATE_ADD(
                        NOW(),
                        INTERVAL ? SECOND
                    )

            WHERE id = ?
            `,
            [
                selected.id,
                OFFER_SECONDS,
                orderId
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
                orderId,
                selected.id
            ]
        );

        await addHistory(
            connection,
            orderId,
            order.status,
            "offered",
            "system"
        );

        const [expires] =
            await connection.execute(
                `
                SELECT offer_expires_at
                FROM orders
                WHERE id = ?
                `,
                [orderId]
            );

        await connection.commit();

        /*
           إرسال الطلب للسائق
        */

        io.to(
            `driver_${selected.id}`
        ).emit(
            "new_order_offer",
            {
                order_id: Number(orderId),

                restaurant_name:
                    order.restaurant_name,

                pickup_lat:
                    Number(order.pickup_lat),

                pickup_lng:
                    Number(order.pickup_lng),

                delivery_lat:
                    Number(order.delivery_lat),

                delivery_lng:
                    Number(order.delivery_lng),

                food_price:
                    Number(order.food_price),

                delivery_fee:
                    Number(order.delivery_fee),

                platform_fee:
                    PLATFORM_FEE,

                mode:
                    selected.mode,

                distance_to_restaurant:
                    selected.distance,

                expires_at:
                    expires[0]?.offer_expires_at
            }
        );

        /*
           مراقبة انتهاء الـ20 ثانية
        */

        setTimeout(
            () => checkOfferExpiration(
                orderId,
                selected.id
            ).catch(console.error),

            (OFFER_SECONDS * 1000) + 500
        );

    } catch (error) {

        try {
            await connection.rollback();
        } catch {}

        console.error(
            "Dispatch error:",
            error
        );

    } finally {

        connection.release();
    }
}

/* =====================================================
   OFFER EXPIRATION
===================================================== */

async function checkOfferExpiration(
    orderId,
    driverId
) {

    const connection =
        await db.getConnection();

    try {

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

        if (!orders.length) {

            await connection.rollback();
            return;
        }

        const order = orders[0];

        /*
           ربما السائق قبل بالفعل.
        */

        if (
            order.status !== "offered" ||
            Number(
                order.offered_driver_id
            ) !== Number(driverId)
        ) {

            await connection.rollback();
            return;
        }

        const [expired] =
            await connection.execute(
                `
                SELECT id
                FROM orders

                WHERE id = ?

                AND offer_expires_at IS NOT NULL

                AND offer_expires_at <= NOW()
                `,
                [orderId]
            );

        if (!expired.length) {

            await connection.rollback();
            return;
        }

        await connection.execute(
            `
            UPDATE order_dispatch_log

            SET status = 'expired'

            WHERE order_id = ?
            AND driver_id = ?
            AND status = 'offered'
            `,
            [
                orderId,
                driverId
            ]
        );

        /*
           نقص نقطة واحدة
        */

        await connection.execute(
            `
            UPDATE drivers

            SET driver_points =
                GREATEST(
                    0,
                    driver_points - 1
                )

            WHERE id = ?
            `,
            [driverId]
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

        await addHistory(
            connection,
            orderId,
            "offered",
            "pending",
            "system"
        );

        await connection.commit();

        io.to(
            `driver_${driverId}`
        ).emit(
            "offer_expired",
            {
                order_id: orderId
            }
        );

        /*
           الآن مباشرة للسائق التالي
        */

        dispatchOrder(orderId)
            .catch(console.error);

    } catch (error) {

        try {
            await connection.rollback();
        } catch {}

        console.error(
            "Expiration error:",
            error
        );

    } finally {

        connection.release();
    }
}

/* =====================================================
   EXPIRATION WORKER
===================================================== */

async function expirationWorker() {

    try {

        const [rows] =
            await db.execute(
                `
                SELECT
                    id,
                    offered_driver_id

                FROM orders

                WHERE status = 'offered'

                AND offer_expires_at IS NOT NULL

                AND offer_expires_at <= NOW()

                LIMIT 100
                `
            );

        for (const row of rows) {

            await checkOfferExpiration(
                Number(row.id),
                Number(row.offered_driver_id)
            );
        }

    } catch (error) {

        console.error(
            "Expiration worker:",
            error
        );
    }
}

setInterval(
    expirationWorker,
    5000
);

/* =====================================================
   SOCKET AUTH
===================================================== */

io.use(
    async (socket, next) => {

        try {

            const token =
                socket.handshake.auth?.token;

            if (!token) {

                return next(
                    new Error(
                        "Authentication required"
                    )
                );
            }

            const decoded =
                jwt.verify(
                    token,
                    JWT_SECRET
                );

            let table;

            if (
                decoded.role === "driver"
            ) {
                table = "drivers";
            }

            else if (
                decoded.role === "restaurant"
            ) {
                table = "restaurants";
            }

            else if (
                decoded.role === "admin"
            ) {
                table = "admins";
            }

            else {

                return next(
                    new Error(
                        "Invalid role"
                    )
                );
            }

            const [rows] =
                await db.execute(
                    `
                    SELECT is_active
                    FROM ${table}

                    WHERE id = ?

                    LIMIT 1
                    `,
                    [decoded.id]
                );

            if (
                !rows.length ||
                Number(
                    rows[0].is_active
                ) !== 1
            ) {

                return next(
                    new Error(
                        "Account inactive"
                    )
                );
            }

            socket.user = decoded;

            next();

        } catch {

            next(
                new Error(
                    "Invalid socket token"
                )
            );
        }
    }
);

/* =====================================================
   SOCKET CONNECTION
===================================================== */

io.on(
    "connection",
    socket => {

        const {
            id,
            role
        } = socket.user;

        /*
           DRIVER
        */

        if (role === "driver") {

            socket.join(
                `driver_${id}`
            );

            /*
               جلسة واحدة للسائق
            */

            if (
                connectedDrivers.has(id)
            ) {

                const oldSocket =
                    connectedDrivers.get(id);

                io.sockets.sockets
                    .get(oldSocket)
                    ?.disconnect(true);
            }

            connectedDrivers.set(
                id,
                socket.id
            );
        }

        /*
           RESTAURANT
        */

        if (
            role === "restaurant"
        ) {

            socket.join(
                `restaurant_${id}`
            );

            connectedRestaurants.set(
                id,
                socket.id
            );
        }

        /*
           ADMIN
        */

        if (role === "admin") {

            socket.join(
                "admin_room"
            );

            connectedAdmins.add(
                socket.id
            );
        }

        /*
           ================================
           DRIVER LOCATION
           ================================
        */

        socket.on(
            "update_location",
            async data => {

                if (role !== "driver") {
                    return;
                }

                const lat =
                    Number(data?.lat);

                const lng =
                    Number(data?.lng);

                if (
                    !validCoordinates(
                        lat,
                        lng
                    )
                ) {
                    return;
                }

                try {

                    await db.execute(
                        `
                        UPDATE drivers

                        SET
                            lat = ?,
                            lng = ?,
                            last_location_update =
                                NOW()

                        WHERE id = ?
                        AND is_active = 1
                        `,
                        [
                            lat,
                            lng,
                            id
                        ]
                    );

                    /*
                       الإدارة
                    */

                    io.to(
                        "admin_room"
                    ).emit(
                        "driver_location_updated",
                        {
                            driver_id:
                                Number(id),

                            lat,
                            lng,

                            updated_at:
                                new Date()
                        }
                    );

                    /*
                       المطاعم التي لديها
                       طلبات لهذا السائق
                    */

                    const [orders] =
                        await db.execute(
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
                            [id]
                        );

                    for (
                        const order of orders
                    ) {

                        io.to(
                            `restaurant_${order.restaurant_id}`
                        ).emit(
                            "driver_location_updated",
                            {
                                order_id:
                                    Number(order.id),

                                driver_id:
                                    Number(id),

                                lat,
                                lng
                            }
                        );
                    }

                } catch (error) {

                    console.error(
                        "Location update:",
                        error
                    );
                }
            }
        );

        /*
           ================================
           DISCONNECT
           ================================
        */

        socket.on(
            "disconnect",
            async () => {

                try {

                    if (
                        role === "driver" &&
                        connectedDrivers.get(id)
                            === socket.id
                    ) {

                        connectedDrivers.delete(
                            id
                        );

                        await db.execute(
                            `
                            UPDATE drivers

                            SET is_online = 0

                            WHERE id = ?
                            `,
                            [id]
                        );

                        io.to(
                            "admin_room"
                        ).emit(
                            "driver_status_updated",
                            {
                                driver_id:
                                    Number(id),

                                is_online:
                                    false
                            }
                        );
                    }

                    if (
                        role === "restaurant" &&
                        connectedRestaurants.get(id)
                            === socket.id
                    ) {

                        connectedRestaurants.delete(
                            id
                        );
                    }

                    if (
                        role === "admin"
                    ) {

                        connectedAdmins.delete(
                            socket.id
                        );
                    }

                } catch {}
            }
        );
    }
);

/* =====================================================
   AUTH - RESTAURANT
===================================================== */

app.post(
    "/api/auth/restaurant/login",
    authLimiter,
    async (req, res) => {

        const phone =
            normalizePhone(
                req.body.phone
            );

        const password =
            req.body.password;

        if (
            !phone ||
            typeof password !== "string"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Phone and password are required."
            });
        }

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT
                        id,
                        name,
                        password_hash,
                        is_active

                    FROM restaurants

                    WHERE phone = ?

                    LIMIT 1
                    `,
                    [phone]
                );

            if (
                !rows.length ||
                Number(
                    rows[0].is_active
                ) !== 1 ||
                !(
                    await bcrypt.compare(
                        password,
                        rows[0].password_hash
                    )
                )
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid credentials."
                });
            }

            res.json({
                success: true,

                token:
                    generateToken(
                        rows[0].id,
                        "restaurant"
                    ),

                restaurant: {
                    id: rows[0].id,
                    name: rows[0].name
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   AUTH - DRIVER
===================================================== */

app.post(
    "/api/auth/driver/login",
    authLimiter,
    async (req, res) => {

        const phone =
            normalizePhone(
                req.body.phone
            );

        const password =
            req.body.password;

        if (
            !phone ||
            typeof password !== "string"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Phone and password are required."
            });
        }

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT
                        id,
                        name,
                        password_hash,
                        is_active

                    FROM drivers

                    WHERE phone = ?

                    LIMIT 1
                    `,
                    [phone]
                );

            if (
                !rows.length ||
                Number(
                    rows[0].is_active
                ) !== 1 ||
                !(
                    await bcrypt.compare(
                        password,
                        rows[0].password_hash
                    )
                )
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid credentials."
                });
            }

            res.json({
                success: true,

                token:
                    generateToken(
                        rows[0].id,
                        "driver"
                    ),

                driver: {
                    id: rows[0].id,
                    name: rows[0].name
                }
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   AUTH - ADMIN
===================================================== */

app.post(
    "/api/auth/admin/login",
    authLimiter,
    async (req, res) => {

        const username =
            cleanString(
                req.body.username,
                100
            );

        const password =
            req.body.password;

        if (
            !username ||
            typeof password !== "string"
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Username and password are required."
            });
        }

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT
                        id,
                        password_hash,
                        is_active

                    FROM admins

                    WHERE username = ?

                    LIMIT 1
                    `,
                    [username]
                );

            if (
                !rows.length ||
                Number(
                    rows[0].is_active
                ) !== 1 ||
                !(
                    await bcrypt.compare(
                        password,
                        rows[0].password_hash
                    )
                )
            ) {

                return res.status(401).json({
                    success: false,
                    message:
                        "Invalid credentials."
                });
            }

            res.json({
                success: true,

                token:
                    generateToken(
                        rows[0].id,
                        "admin"
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   DRIVER ONLINE / OFFLINE
===================================================== */

app.post(
    "/api/driver/status",
    authenticate("driver"),
    async (req, res) => {

        const online =
            req.body.is_online === true;

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT
                        id,
                        is_active,
                        current_orders_count

                    FROM drivers

                    WHERE id = ?

                    LIMIT 1
                    `,
                    [req.user.id]
                );

            if (
                !rows.length ||
                Number(
                    rows[0].is_active
                ) !== 1
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Driver inactive."
                });
            }

            /*
               لا يمكنه الخروج Offline
               ولديه طلبات.
            */

            if (
                !online &&
                Number(
                    rows[0].current_orders_count
                ) > 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        "You cannot go offline while you have active orders."
                });
            }

            await db.execute(
                `
                UPDATE drivers

                SET is_online = ?

                WHERE id = ?
                `,
                [
                    online ? 1 : 0,
                    req.user.id
                ]
            );

            io.to(
                "admin_room"
            ).emit(
                "driver_status_updated",
                {
                    driver_id:
                        Number(req.user.id),

                    is_online:
                        online
                }
            );

            res.json({
                success: true,
                is_online: online
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   DRIVER LOCATION REST
===================================================== */

app.post(
    "/api/driver/location",
    authenticate("driver"),
    async (req, res) => {

        const lat =
            Number(req.body.lat);

        const lng =
            Number(req.body.lng);

        if (
            !validCoordinates(
                lat,
                lng
            )
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid coordinates."
            });
        }

        try {

            await db.execute(
                `
                UPDATE drivers

                SET
                    lat = ?,
                    lng = ?,
                    last_location_update =
                        NOW()

                WHERE id = ?
                AND is_active = 1
                `,
                [
                    lat,
                    lng,
                    req.user.id
                ]
            );

            io.to(
                "admin_room"
            ).emit(
                "driver_location_updated",
                {
                    driver_id:
                        Number(req.user.id),

                    lat,
                    lng
                }
            );

            res.json({
                success: true
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);
/* =====================================================
   CREATE ORDER
===================================================== */

app.post(
    "/api/restaurant/orders",
    authenticate("restaurant"),
    async (req, res) => {

        const restaurantId =
            Number(req.user.id);

        const customerName =
            cleanString(
                req.body.customer_name,
                150
            );

        const customerPhone =
            normalizePhone(
                req.body.customer_phone
            );

        const customerAddress =
            cleanString(
                req.body.customer_address,
                500
            );

        const pickupLat =
            Number(req.body.pickup_lat);

        const pickupLng =
            Number(req.body.pickup_lng);

        const deliveryLat =
            Number(req.body.delivery_lat);

        const deliveryLng =
            Number(req.body.delivery_lng);

        const foodPrice =
            Number(req.body.food_price);

        const deliveryFee =
            Number(req.body.delivery_fee);

        if (
            !customerName ||
            !customerPhone ||
            !customerAddress ||

            !validCoordinates(
                pickupLat,
                pickupLng
            ) ||

            !validCoordinates(
                deliveryLat,
                deliveryLng
            ) ||

            !validMoney(foodPrice) ||

            !validMoney(deliveryFee) ||

            deliveryFee <= 0
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order data."
            });
        }

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();

            const [restaurants] =
                await connection.execute(
                    `
                    SELECT
                        id,
                        name,
                        is_active

                    FROM restaurants

                    WHERE id = ?

                    FOR UPDATE
                    `,
                    [restaurantId]
                );

            if (
                !restaurants.length ||
                Number(
                    restaurants[0].is_active
                ) !== 1
            ) {

                await connection.rollback();

                return res.status(403).json({
                    success: false,
                    message:
                        "Restaurant inactive."
                });
            }

            /*
               OTP يتم إنشاؤه عند إنشاء الطلب
               ولا يظهر إلا للسائق بعد قبوله.
            */

            const otp =
                generateOTP();

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
                        payment_status
                    )

                    VALUES
                    (
                        ?, ?, ?, ?,
                        ?, ?,
                        ?, ?,
                        ?, ?,
                        ?,
                        ?,
                        'pending',
                        'pending'
                    )
                    `,
                    [
                        restaurantId,

                        customerName,
                        customerPhone,
                        customerAddress,

                        pickupLat,
                        pickupLng,

                        deliveryLat,
                        deliveryLng,

                        foodPrice,
                        deliveryFee,

                        PLATFORM_FEE,

                        otp
                    ]
                );

            const orderId =
                Number(result.insertId);

            await addHistory(
                connection,
                orderId,
                null,
                "pending",
                "restaurant",
                restaurantId
            );

            await connection.commit();

            /*
               بدء البحث عن السائق
            */

            dispatchOrder(orderId)
                .catch(console.error);

            res.status(201).json({
                success: true,

                order_id:
                    orderId,

                message:
                    "Order created successfully."
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Create order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   DRIVER ACCEPT
===================================================== */

app.post(
    "/api/driver/orders/accept",
    authenticate("driver"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        const driverId =
            Number(req.user.id);

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        const connection =
            await db.getConnection();

        try {

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

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            /*
               هذا العرض بالذات
               موجه لهذا السائق
            */

            if (
                order.status !== "offered" ||
                Number(
                    order.offered_driver_id
                ) !== driverId
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Offer unavailable."
                });
            }

            /*
               التأكد من أن الـ20 ثانية
               لم تنته
            */

            const [notExpired] =
                await connection.execute(
                    `
                    SELECT id

                    FROM orders

                    WHERE id = ?

                    AND offer_expires_at > NOW()
                    `,
                    [orderId]
                );

            if (!notExpired.length) {

                await connection.rollback();

                await checkOfferExpiration(
                    orderId,
                    driverId
                );

                return res.status(400).json({
                    success: false,
                    message:
                        "Offer expired."
                });
            }

            /*
               قفل السائق
            */

            const [drivers] =
                await connection.execute(
                    `
                    SELECT
                        id,
                        is_active,
                        is_online,
                        current_orders_count,
                        max_concurrent_orders

                    FROM drivers

                    WHERE id = ?

                    FOR UPDATE
                    `,
                    [driverId]
                );

            if (
                !drivers.length ||
                Number(
                    drivers[0].is_active
                ) !== 1 ||
                Number(
                    drivers[0].is_online
                ) !== 1
            ) {

                await connection.rollback();

                return res.status(403).json({
                    success: false,
                    message:
                        "Driver is not available."
                });
            }

            const current =
                Number(
                    drivers[0]
                        .current_orders_count
                );

            const max =
                Number(
                    drivers[0]
                        .max_concurrent_orders
                ) || 1;

            /*
               لا يسمح بتجاوز الحد.
            */

            if (current >= max) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Driver cannot accept another order."
                });
            }

            /*
               قبول الطلب
            */

            const [updated] =
                await connection.execute(
                    `
                    UPDATE orders

                    SET
                        status = 'accepted',
                        driver_id = ?,
                        offered_driver_id = NULL,
                        offer_expires_at = NULL,
                        accepted_at = NOW()

                    WHERE id = ?

                    AND status = 'offered'

                    AND offered_driver_id = ?
                    `,
                    [
                        driverId,
                        orderId,
                        driverId
                    ]
                );

            if (
                updated.affectedRows !== 1
            ) {

                await connection.rollback();

                return res.status(409).json({
                    success: false,
                    message:
                        "Offer was already handled."
                });
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
                    driverId
                ]
            );

            /*
               زيادة الطلبات النشطة للسائق
            */

            await connection.execute(
                `
                UPDATE drivers

                SET current_orders_count =
                    current_orders_count + 1

                WHERE id = ?
                `,
                [driverId]
            );

            await addHistory(
                connection,
                orderId,
                "offered",
                "accepted",
                "driver",
                driverId
            );

            await connection.commit();

            /*
               OTP يظهر للسائق
            */

            io.to(
                `driver_${driverId}`
            ).emit(
                "order_accepted",
                {
                    order_id: orderId,

                    otp_code:
                        order.otp_code
                }
            );

            /*
               المطعم يعرف أن سائقا قبل
            */

            io.to(
                `restaurant_${order.restaurant_id}`
            ).emit(
                "driver_assigned",
                {
                    order_id:
                        orderId,

                    driver_id:
                        driverId
                }
            );

            res.json({
                success: true,

                order_id:
                    orderId,

                otp_code:
                    order.otp_code
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Accept order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   DRIVER REJECT
===================================================== */

app.post(
    "/api/driver/orders/reject",
    authenticate("driver"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        const driverId =
            Number(req.user.id);

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        const connection =
            await db.getConnection();

        try {

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

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            if (
                order.status !== "offered" ||
                Number(
                    order.offered_driver_id
                ) !== driverId
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Offer unavailable."
                });
            }

            const [notExpired] =
                await connection.execute(
                    `
                    SELECT id

                    FROM orders

                    WHERE id = ?

                    AND offer_expires_at > NOW()
                    `,
                    [orderId]
                );

            if (!notExpired.length) {

                await connection.rollback();

                await checkOfferExpiration(
                    orderId,
                    driverId
                );

                return res.status(400).json({
                    success: false,
                    message:
                        "Offer expired."
                });
            }

            /*
               تسجيل الرفض
            */

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
                    driverId
                ]
            );

            /*
               الرفض ينقص نقطة
            */

            await connection.execute(
                `
                UPDATE drivers

                SET driver_points =
                    GREATEST(
                        0,
                        driver_points - 1
                    )

                WHERE id = ?
                `,
                [driverId]
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

            await addHistory(
                connection,
                orderId,
                "offered",
                "pending",
                "driver",
                driverId
            );

            await connection.commit();

            /*
               السائق التالي
            */

            dispatchOrder(orderId)
                .catch(console.error);

            res.json({
                success: true,
                message:
                    "Order rejected."
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Reject order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   RESTAURANT VERIFY OTP
===================================================== */

app.post(
    "/api/restaurant/orders/verify-otp",
    authenticate("restaurant"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        const otp =
            String(
                req.body.otp_code || ""
            ).trim();

        if (
            !validId(orderId) ||
            !/^\d{4}$/.test(otp)
        ) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid OTP."
            });
        }

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *
                    FROM orders

                    WHERE id = ?
                    AND restaurant_id = ?

                    FOR UPDATE
                    `,
                    [
                        orderId,
                        req.user.id
                    ]
                );

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            /*
               لا يمكن استعمال OTP
               مرتين.
            */

            if (
                order.status !== "accepted"
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Order is not ready for pickup."
                });
            }

            if (
                String(order.otp_code) !== otp
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Incorrect OTP."
                });
            }

            /*
               هنا تم التأكد أن السائق
               هو السائق الصحيح.

               الآن:
               السائق يدفع للمطعم:

               سعر الطعام
               +
               1 دينار عمولتك
            */

            const amountToPayRestaurant =
                Number(order.food_price) +
                PLATFORM_FEE;

            await connection.execute(
                `
                UPDATE orders

                SET
                    status = 'picking_up',
                    restaurant_paid_at = NOW(),
                    pickup_verified_at = NOW(),
                    platform_fee_recorded = 1

                WHERE id = ?
                `,
                [orderId]
            );

            /*
               إضافة الدين على المطعم
            */

            await connection.execute(
                `
                UPDATE restaurants

                SET balance_due =
                    balance_due + ?

                WHERE id = ?
                `,
                [
                    PLATFORM_FEE,
                    req.user.id
                ]
            );

            /*
               تسجيل العمولة
            */

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

                VALUES
                (
                    ?,
                    ?,
                    ?,
                    'platform_fee',
                    ?
                )
                `,
                [
                    req.user.id,
                    orderId,
                    PLATFORM_FEE,
                    `Platform fee for order #${orderId}`
                ]
            );

            await addHistory(
                connection,
                orderId,
                "accepted",
                "picking_up",
                "restaurant",
                req.user.id
            );

            await connection.commit();

            /*
               إخبار السائق:
               OTP صحيح
               يمكنه أخذ الطعام
            */

            io.to(
                `driver_${order.driver_id}`
            ).emit(
                "pickup_verified",
                {
                    order_id:
                        orderId,

                    amount_to_pay_restaurant:
                        amountToPayRestaurant,

                    food_price:
                        Number(order.food_price),

                    platform_fee:
                        PLATFORM_FEE
                }
            );

            res.json({
                success: true,

                message:
                    "OTP verified. Pickup confirmed.",

                amount_to_pay_restaurant:
                    amountToPayRestaurant
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "OTP verification:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);
/* =====================================================
   DRIVER START DELIVERY
===================================================== */

app.post(
    "/api/driver/orders/start",
    authenticate("driver"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *

                    FROM orders

                    WHERE id = ?
                    AND driver_id = ?

                    FOR UPDATE
                    `,
                    [
                        orderId,
                        req.user.id
                    ]
                );

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            if (
                order.status !==
                "picking_up"
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Order is not ready."
                });
            }

            await connection.execute(
                `
                UPDATE orders

                SET
                    status = 'delivering',
                    delivery_started_at = NOW()

                WHERE id = ?
                `,
                [orderId]
            );

            await addHistory(
                connection,
                orderId,
                "picking_up",
                "delivering",
                "driver",
                req.user.id
            );

            await connection.commit();

            /*
               المطعم يعرف أن التوصيل بدأ
            */

            io.to(
                `restaurant_${order.restaurant_id}`
            ).emit(
                "delivery_started",
                {
                    order_id:
                        orderId
                }
            );

            res.json({
                success: true,
                message:
                    "Delivery started."
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Start delivery:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   DRIVER COMPLETE
===================================================== */

app.post(
    "/api/driver/orders/complete",
    authenticate("driver"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *

                    FROM orders

                    WHERE id = ?
                    AND driver_id = ?

                    FOR UPDATE
                    `,
                    [
                        orderId,
                        req.user.id
                    ]
                );

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            if (
                order.status !==
                "delivering"
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Order is not being delivered."
                });
            }

            /*
               دخل السائق
               = delivery_fee
            */

            const driverEarnings =
                Number(
                    order.delivery_fee
                );

            await connection.execute(
                `
                UPDATE orders

                SET
                    status = 'completed',
                    payment_status = 'paid',
                    completed_at = NOW()

                WHERE id = ?
                `,
                [orderId]
            );

            /*
               إنقاص الطلبات النشطة
               وزيادة دخل السائق
            */

            await connection.execute(
                `
                UPDATE drivers

                SET
                    current_orders_count =
                        GREATEST(
                            0,
                            current_orders_count - 1
                        ),

                    wallet_balance =
                        wallet_balance + ?,

                    total_earnings =
                        total_earnings + ?

                WHERE id = ?
                `,
                [
                    driverEarnings,
                    driverEarnings,
                    req.user.id
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

                VALUES
                (
                    ?,
                    ?,
                    ?,
                    'delivery_earning',
                    ?
                )
                `,
                [
                    req.user.id,
                    orderId,
                    driverEarnings,
                    `Delivery earning for order #${orderId}`
                ]
            );

            await addHistory(
                connection,
                orderId,
                "delivering",
                "completed",
                "driver",
                req.user.id
            );

            await connection.commit();

            io.to(
                `restaurant_${order.restaurant_id}`
            ).emit(
                "order_completed",
                {
                    order_id:
                        orderId
                }
            );

            io.to(
                "admin_room"
            ).emit(
                "order_completed",
                {
                    order_id:
                        orderId
                }
            );

            res.json({
                success: true,

                message:
                    "Order completed.",

                driver_earning:
                    driverEarnings
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Complete order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   RESTAURANT CANCEL
===================================================== */

app.post(
    "/api/restaurant/orders/cancel",
    authenticate("restaurant"),
    async (req, res) => {

        const orderId =
            Number(req.body.order_id);

        const reason =
            cleanString(
                req.body.reason ||
                "Restaurant cancellation",
                500
            );

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        const connection =
            await db.getConnection();

        try {

            await connection.beginTransaction();

            const [orders] =
                await connection.execute(
                    `
                    SELECT *

                    FROM orders

                    WHERE id = ?
                    AND restaurant_id = ?

                    FOR UPDATE
                    `,
                    [
                        orderId,
                        req.user.id
                    ]
                );

            if (!orders.length) {

                await connection.rollback();

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                orders[0];

            if (
                ["completed", "cancelled"]
                    .includes(order.status)
            ) {

                await connection.rollback();

                return res.status(400).json({
                    success: false,
                    message:
                        "Order cannot be cancelled."
                });
            }

            await connection.execute(
                `
                UPDATE orders

                SET
                    status = 'cancelled',
                    cancellation_reason = ?,
                    cancelled_at = NOW(),
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
               إذا كان السائق قد أخذ الطلب
               ننقص عدد طلباته النشطة.
            */

            if (
                order.driver_id &&
                [
                    "accepted",
                    "picking_up",
                    "delivering"
                ].includes(order.status)
            ) {

                await connection.execute(
                    `
                    UPDATE drivers

                    SET current_orders_count =
                        GREATEST(
                            0,
                            current_orders_count - 1
                        )

                    WHERE id = ?
                    `,
                    [order.driver_id]
                );

                io.to(
                    `driver_${order.driver_id}`
                ).emit(
                    "order_cancelled",
                    {
                        order_id:
                            orderId
                    }
                );
            }

            /*
               إذا كان مازال عند سائق
               في مرحلة offer
            */

            if (
                order.offered_driver_id
            ) {

                await connection.execute(
                    `
                    UPDATE order_dispatch_log

                    SET status = 'expired'

                    WHERE order_id = ?
                    AND driver_id = ?
                    AND status = 'offered'
                    `,
                    [
                        orderId,
                        order.offered_driver_id
                    ]
                );

                io.to(
                    `driver_${order.offered_driver_id}`
                ).emit(
                    "order_cancelled",
                    {
                        order_id:
                            orderId
                    }
                );
            }

            await addHistory(
                connection,
                orderId,
                order.status,
                "cancelled",
                "restaurant",
                req.user.id
            );

            await connection.commit();

            res.json({
                success: true,
                message:
                    "Order cancelled."
            });

        } catch (error) {

            try {
                await connection.rollback();
            } catch {}

            console.error(
                "Cancel order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });

        } finally {

            connection.release();
        }
    }
);

/* =====================================================
   GET SINGLE ORDER
===================================================== */

app.get(
    "/api/orders/:id",
    authenticate(
        "restaurant",
        "driver",
        "admin"
    ),
    async (req, res) => {

        const orderId =
            Number(req.params.id);

        if (!validId(orderId)) {

            return res.status(400).json({
                success: false,
                message:
                    "Invalid order ID."
            });
        }

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT

                        o.*,

                        r.name AS restaurant_name,
                        r.phone AS restaurant_phone,
                        r.address AS restaurant_address,

                        d.name AS driver_name,
                        d.phone AS driver_phone,
                        d.lat AS driver_lat,
                        d.lng AS driver_lng

                    FROM orders o

                    JOIN restaurants r
                        ON r.id = o.restaurant_id

                    LEFT JOIN drivers d
                        ON d.id = o.driver_id

                    WHERE o.id = ?

                    LIMIT 1
                    `,
                    [orderId]
                );

            if (!rows.length) {

                return res.status(404).json({
                    success: false,
                    message:
                        "Order not found."
                });
            }

            const order =
                rows[0];

            /*
               حماية البيانات
            */

            if (
                req.user.role ===
                "restaurant" &&
                Number(
                    order.restaurant_id
                ) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Access denied."
                });
            }

            if (
                req.user.role ===
                "driver" &&

                Number(order.driver_id) !==
                Number(req.user.id) &&

                Number(
                    order.offered_driver_id
                ) !==
                Number(req.user.id)
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        "Access denied."
                });
            }

            /*
               OTP لا يظهر للسائق
               إلا بعد القبول.
            */

            if (
                req.user.role ===
                "driver" &&
                ![
                    "accepted",
                    "picking_up",
                    "delivering"
                ].includes(order.status)
            ) {

                delete order.otp_code;
            }

            res.json({
                success: true,
                order
            });

        } catch (error) {

            console.error(
                "Get order:",
                error
            );

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   RESTAURANT DASHBOARD
===================================================== */

app.get(
    "/api/restaurant/dashboard",
    authenticate("restaurant"),
    async (req, res) => {

        try {

            const restaurantId =
                Number(req.user.id);

            /*
               عدد الطلبات اليوم
            */

            const [[stats]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS today_orders

                    FROM orders

                    WHERE restaurant_id = ?

                    AND DATE(created_at) =
                        CURDATE()
                    `,
                    [restaurantId]
                );

            /*
               المطعم
            */

            const [[restaurant]] =
                await db.execute(
                    `
                    SELECT
                        id,
                        name,
                        phone,
                        address,
                        balance_due

                    FROM restaurants

                    WHERE id = ?
                    `,
                    [restaurantId]
                );

            /*
               عدد السائقين المتاحين
            */

            const [[drivers]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS online_drivers

                    FROM drivers

                    WHERE is_online = 1
                    AND is_active = 1
                    `
                );

            res.json({

                success: true,

                restaurant,

                today_orders:
                    Number(
                        stats.today_orders
                    ),

                online_drivers:
                    Number(
                        drivers.online_drivers
                    ),

                balance_due:
                    Number(
                        restaurant?.balance_due ||
                        0
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   DRIVER DASHBOARD
===================================================== */

app.get(
    "/api/driver/dashboard",
    authenticate("driver"),
    async (req, res) => {

        try {

            const driverId =
                Number(req.user.id);

            const [[stats]] =
                await db.execute(
                    `
                    SELECT

                        COUNT(
                            CASE
                                WHEN
                                    status = 'completed'
                                    AND DATE(completed_at)
                                        = CURDATE()
                                THEN 1
                            END
                        ) AS today_orders,

                        COALESCE(
                            SUM(
                                CASE
                                    WHEN
                                        status = 'completed'
                                        AND DATE(completed_at)
                                            = CURDATE()
                                    THEN delivery_fee
                                    ELSE 0
                                END
                            ),
                            0
                        ) AS today_income

                    FROM orders

                    WHERE driver_id = ?
                    `,
                    [driverId]
                );

            const [[driver]] =
                await db.execute(
                    `
                    SELECT

                        id,
                        name,
                        phone,
                        is_online,
                        current_orders_count,
                        max_concurrent_orders,
                        wallet_balance,
                        total_earnings,
                        driver_points

                    FROM drivers

                    WHERE id = ?
                    `,
                    [driverId]
                );

            res.json({

                success: true,

                driver,

                today_orders:
                    Number(
                        stats.today_orders
                    ),

                today_income:
                    Number(
                        stats.today_income
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   DRIVER WALLET
===================================================== */

app.get(
    "/api/driver/wallet",
    authenticate("driver"),
    async (req, res) => {

        try {

            const [[driver]] =
                await db.execute(
                    `
                    SELECT
                        wallet_balance,
                        total_earnings

                    FROM drivers

                    WHERE id = ?
                    `,
                    [req.user.id]
                );

            const [transactions] =
                await db.execute(
                    `
                    SELECT
                        id,
                        order_id,
                        amount,
                        type,
                        note,
                        created_at

                    FROM driver_transactions

                    WHERE driver_id = ?

                    ORDER BY created_at DESC

                    LIMIT 200
                    `,
                    [req.user.id]
                );

            res.json({
                success: true,
                wallet: driver,
                transactions
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);
/* =====================================================
   RESTAURANT ORDERS
===================================================== */

app.get(
    "/api/restaurant/orders",
    authenticate("restaurant"),
    async (req, res) => {

        try {

            const [orders] =
                await db.execute(
                    `
                    SELECT

                        o.id,

                        o.customer_name,
                        o.customer_phone,
                        o.customer_address,

                        o.pickup_lat,
                        o.pickup_lng,

                        o.delivery_lat,
                        o.delivery_lng,

                        o.food_price,
                        o.delivery_fee,
                        o.platform_fee,

                        o.status,

                        o.created_at,
                        o.accepted_at,
                        o.restaurant_paid_at,
                        o.pickup_verified_at,
                        o.delivery_started_at,
                        o.completed_at,
                        o.cancelled_at,

                        d.id AS driver_id,
                        d.name AS driver_name,
                        d.phone AS driver_phone,
                        d.lat AS driver_lat,
                        d.lng AS driver_lng

                    FROM orders o

                    LEFT JOIN drivers d
                        ON d.id = o.driver_id

                    WHERE o.restaurant_id = ?

                    ORDER BY
                        o.created_at DESC

                    LIMIT 500
                    `,
                    [req.user.id]
                );

            res.json({
                success: true,
                orders
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   DRIVER ORDERS
===================================================== */

app.get(
    "/api/driver/orders",
    authenticate("driver"),
    async (req, res) => {

        try {

            const [orders] =
                await db.execute(
                    `
                    SELECT

                        o.*,

                        r.name AS restaurant_name,
                        r.phone AS restaurant_phone,
                        r.address AS restaurant_address,
                        r.lat AS restaurant_lat,
                        r.lng AS restaurant_lng

                    FROM orders o

                    JOIN restaurants r
                        ON r.id = o.restaurant_id

                    WHERE o.driver_id = ?

                    ORDER BY
                        o.created_at DESC

                    LIMIT 500
                    `,
                    [req.user.id]
                );

            res.json({
                success: true,
                orders
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   ADMIN DASHBOARD
===================================================== */

app.get(
    "/api/admin/dashboard",
    authenticate("admin"),
    async (req, res) => {

        try {

            /*
               عدد المطاعم
            */

            const [[restaurants]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS total

                    FROM restaurants

                    WHERE is_active = 1
                    `
                );

            /*
               عدد السائقين
            */

            const [[drivers]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS total

                    FROM drivers

                    WHERE is_active = 1
                    `
                );

            /*
               السائقون المتاحون
            */

            const [[onlineDrivers]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS total

                    FROM drivers

                    WHERE is_active = 1

                    AND is_online = 1
                    `
                );

            /*
               طلبات اليوم
            */

            const [[orders]] =
                await db.execute(
                    `
                    SELECT
                        COUNT(*) AS total

                    FROM orders

                    WHERE DATE(created_at)
                        = CURDATE()
                    `
                );

            /*
               دخل المنصة اليوم
            */

            const [[income]] =
                await db.execute(
                    `
                    SELECT

                        COALESCE(
                            SUM(platform_fee),
                            0
                        ) AS total

                    FROM orders

                    WHERE
                        platform_fee_recorded = 1

                    AND DATE(pickup_verified_at)
                        = CURDATE()
                    `
                );

            /*
               إجمالي ديون المطاعم
            */

            const [[due]] =
                await db.execute(
                    `
                    SELECT

                        COALESCE(
                            SUM(balance_due),
                            0
                        ) AS total

                    FROM restaurants

                    WHERE is_active = 1
                    `
                );

            res.json({

                success: true,

                total_restaurants:
                    Number(
                        restaurants.total
                    ),

                total_drivers:
                    Number(
                        drivers.total
                    ),

                online_drivers:
                    Number(
                        onlineDrivers.total
                    ),

                today_orders:
                    Number(
                        orders.total
                    ),

                today_platform_income:
                    Number(
                        income.total
                    ),

                cumulative_restaurants_due:
                    Number(
                        due.total
                    )
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   ADMIN RESTAURANT DEBTS
===================================================== */

app.get(
    "/api/admin/restaurants/debts",
    authenticate("admin"),
    async (req, res) => {

        try {

            const [rows] =
                await db.execute(
                    `
                    SELECT

                        id,
                        name,
                        phone,
                        balance_due

                    FROM restaurants

                    WHERE is_active = 1

                    ORDER BY
                        balance_due DESC
                    `
                );

            res.json({
                success: true,
                restaurants: rows
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   ADMIN ORDERS
===================================================== */

app.get(
    "/api/admin/orders",
    authenticate("admin"),
    async (req, res) => {

        try {

            const [orders] =
                await db.execute(
                    `
                    SELECT

                        o.*,

                        r.name AS restaurant_name,
                        r.phone AS restaurant_phone,

                        d.name AS driver_name,
                        d.phone AS driver_phone,

                        d.lat AS driver_lat,
                        d.lng AS driver_lng

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

            res.json({
                success: true,
                orders
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   ADMIN LIVE MAP
===================================================== */

app.get(
    "/api/admin/drivers/live",
    authenticate("admin"),
    async (req, res) => {

        try {

            const [drivers] =
                await db.execute(
                    `
                    SELECT

                        id,
                        name,
                        phone,

                        lat,
                        lng,

                        is_online,
                        current_orders_count,
                        max_concurrent_orders,

                        driver_points

                    FROM drivers

                    WHERE is_active = 1

                    AND lat IS NOT NULL
                    AND lng IS NOT NULL

                    ORDER BY
                        is_online DESC,
                        current_orders_count ASC
                    `
                );

            res.json({
                success: true,
                drivers
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                message: "Server error."
            });
        }
    }
);

/* =====================================================
   HEALTH CHECK
===================================================== */

app.get(
    "/",
    async (req, res) => {

        try {

            await db.query(
                "SELECT 1"
            );

            res.json({

                success: true,

                message:
                    "HADROUG DELIVERY API is running.",

                database:
                    "connected",

                timestamp:
                    new Date().toISOString()
            });

        } catch {

            res.status(503).json({

                success: false,

                message:
                    "API is running but database is unavailable."
            });
        }
    }
);

/* =====================================================
   404
===================================================== */

app.use(
    (req, res) => {

        res.status(404).json({

            success: false,

            message:
                "Route not found."
        });
    }
);

/* =====================================================
   ERROR HANDLER
===================================================== */

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        res.status(500).json({

            success: false,

            message:
                "Internal server error."
        });
    }
);

/* =====================================================
   START SERVER
===================================================== */

server.listen(
    PORT,
    () => {

        console.log(
            `🚀 HADROUG DELIVERY API running on port ${PORT}`
        );
    }
);
