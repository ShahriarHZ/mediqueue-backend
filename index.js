const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const mysql = require('mysql2/promise');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// Middleware configurations
app.use(cors({
    origin: [process.env.CLIENT_URL || 'http://localhost:3000'],
    credentials: true
}));
app.use(express.json());

// 1. Unified MySQL connection pool targeting XAMPP (Forced IPv4)
// Dynamic MySQL connection pool switching between Railway (Production) and XAMPP (Local)
const db = mysql.createPool({
    host: process.env.DB_HOST ? process.env.DB_HOST.trim() : '127.0.0.1',
    user: process.env.DB_USER ? process.env.DB_USER.trim() : 'root',
    password: process.env.DB_PASSWORD ? process.env.DB_PASSWORD.trim() : '',
    database: process.env.DB_DATABASE ? process.env.DB_DATABASE.trim() : (process.env.DB_NAME || 'mediqueue_db'),
    port: parseInt(process.env.DB_PORT) || 3306,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
    connectTimeout: 15000,
    enableKeepAlive: true,
    keepAliveInitialDelay: 10000
});

// A safe connection handshake check on server load
(async () => {
    try {
        const connection = await db.getConnection();
        console.log("💾 Verified: Smooth connection established with XAMPP MySQL!");
        connection.release(); 
    } catch (err) {
        console.log("⚠️ XAMPP MySQL isn't responding yet. Make sure MySQL is started in XAMPP control panel!");
        console.log("Reason:", err.message);
    }
})();

// Base Connectivity Endpoint
app.get('/', async (req, res) => {
    try {
        await db.query('SELECT 1');
        res.send({ success: true, message: "MediQueue MySQL server is alive and running!" });
    } catch (err) {
        console.error("Database status error:", err);
        res.status(500).send({ success: false, message: "Failed to connect to MySQL database." });
    }
});

// 2. The /register Endpoint
app.post('/register', async (req, res) => {
    console.log("🚀 The backend received a registration request payload:", req.body);
    try {
        let { name, email, photo, password } = req.body;
        
        if (!name || !email || !password) {
            return res.status(400).send({ error: true, message: "Name, email, and password fields are required." });
        }

        const [existingUsers] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        if (existingUsers.length > 0) {
            return res.status(400).send({ error: true, message: "An account with this email already exists." });
        }
        
        const hashedPassword = await bcrypt.hash(password, 10);
        const userPhoto = photo || ""; 

        const [result] = await db.execute(
            'INSERT INTO users (name, email, photo, password) VALUES (?, ?, ?, ?)',
            [name, email, userPhoto, hashedPassword]
        );
        
        const token = jwt.sign({ email }, process.env.JWT_SECRET || 'secret_key', { expiresIn: '7d' });
        console.log(`✅ Successfully inserted user ID: ${result.insertId} into MySQL!`);

        res.send({ 
            success: true, 
            insertedId: result.insertId,
            token,
            user: { name, email, photo: userPhoto }
        });

    } catch (error) {
        console.error("❌ Registration Database Error:", error);
        res.status(500).send({ error: true, message: "Server error during registration workflow." });
    }
});

// 3. The /login Endpoint
app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const [users] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
        const user = users[0];

        if (!user) {
            return res.status(400).send({ error: true, message: "Invalid email or password." });
        }

        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if (!isPasswordMatch) {
            return res.status(400).send({ error: true, message: "Invalid email or password." });
        }

        const token = jwt.sign({ email: user.email }, process.env.JWT_SECRET || 'secret_key', { expiresIn: '7d' });

        res.send({
            success: true,
            token,
            user: {
                name: user.name,
                email: user.email,
                photo: user.photo
            }
        });
    } catch (error) {
        console.error("Login route error:", error);
        res.status(500).send({ error: true, message: "Server error during login workflow." });
    }
});

// 4. The /jwt Token Generation Endpoint
// ✅ GOOGLE SINGLE SIGN-ON AUTHENTICATION HANDLER
app.post('/jwt', async (req, res) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).send({ error: true, message: "Email is required to sign tokens." });
        }

        // 1. Check if the user exists in your MySQL database users table
        const [userCheck] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);

        let activeUser = null;

        if (userCheck.length > 0) {
            // Existing profile found! Assign them directly.
            activeUser = userCheck[0];
            console.log(`🔑 Existing user authenticated via Google SSO: ${email}`);
        } else {
            // 2. AUTOMATED NEW ACCOUNT CREATION FALLBACK
            // If the user hasn't registered with a password before, save their profile rows on the fly!
            const defaultName = email.split('@')[0]; // Safe backup name string fallback
            
            const insertUserQuery = `
                INSERT INTO users (name, email, photo, role)
                VALUES (?, ?, ?, ?)
            `;
            
            // Note: Since Google profiles do not pass a custom password hash, we pass empty fields 
            // or role attributes depending on your database design schema configurations.
            const [insertResult] = await db.execute(insertUserQuery, [
                defaultName,
                email,
                '', // Default empty string image container placeholder or profile field
                'student' // Default assigned platform clearance role
            ]);

            console.log(`✨ Brand new system user account initialized via Google! Insert Row ID: ${insertResult.insertId}`);
            
            // Mock out the newly written database values to return in the pipeline response block
            activeUser = {
                id: insertResult.insertId,
                name: defaultName,
                email: email,
                photo: '',
                role: 'student'
            };
        }

        // 3. JWT TOKEN SIGNING INTERACTION PIPELINE
        // Generate your normal security token validation signatures exactly like your standard login flow
        const token = jwt.sign(
            { email: activeUser.email, role: activeUser.role }, 
            process.env.ACCESS_TOKEN_SECRET || 'your-fallback-jwt-secret-string', 
            { expiresIn: '7d' }
        );

        // Send token and metadata back down the wire straight to your frontend state managers!
        res.send({ 
            success: true,
            token,
            user: {
                name: activeUser.name,
                email: activeUser.email,
                photo: activeUser.photo || activeUser.picture || ''
            }
        });

    } catch (error) {
        console.error("❌ CRITICAL EXCEPTION DROPPED ALONG GOOGLE SIGN-IN CANYONS:", error);
        res.status(500).send({ error: true, message: `Database synchronization error: ${error.message}` });
    }
});
// 5. The Consolidated /tutors Form Post Endpoint
// Endpoint to handle adding a brand new tutor listing into MySQL
app.post('/tutors', async (req, res) => {
    try {
        // Destructure keys matching the updated payload sent by the frontend
        const { 
            name, 
            photo, 
            subject, 
            price, 
            days, 
            time_slot, 
            slots, 
            start_date, 
            institution, 
            location, 
            teaching_mode, 
            email 
        } = req.body;

        // Validation fallback check to prevent corrupted or unowned records
        if (!email) {
            return res.status(400).send({ 
                error: true, 
                message: "A valid user session email context is required to publish a listing." 
            });
        }

        console.log(`➕ Attempting to write a new tutor profile log for: ${name} (${email})`);

        // SQL Statement matching your exact database schema columns
        const queryStr = `
            INSERT INTO tutors (
                name, photo, subject, price, days, time_slot, 
                slots, start_date, institution, location, teaching_mode, email
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        // Executing using safe array binding arrays to avoid parsing syntax crashes
        const [result] = await db.execute(queryStr, [
            name,
            photo,
            subject,
            parseFloat(price || 0),       // Enforces clean double/decimal precision rates
            days,
            time_slot,
            parseInt(slots || 0),         // Enforces clean integer tracking values
            start_date,                   // Passed as 'YYYY-MM-DD' string format from the client
            institution,
            location,
            teaching_mode,
            email
        ]);

        console.log(`✅ Successfully saved tutor to database. Inserted Row ID: ${result.insertId}`);
        
        // Return .success verification so your frontend components can trigger sweetalerts or toasts safely
        res.send({ 
            success: true, 
            message: "Tutor data record appended successfully!", 
            insertId: result.insertId 
        });

    } catch (error) {
        console.error("❌ MySQL Error during /tutors row insertion pipeline execution:", error);
        res.status(500).send({ 
            error: true, 
            message: "Internal server error failing to write structural SQL record logs." 
        });
    }
});

// Open connection runtime listener
app.listen(port, () => {
    console.log(`🚀 MediQueue MySQL server listening smoothly on port ${port}`);
});


// 1. GET ALL TUTORS (For Home/All Tutors Page)
// Fetch all listed tutors for the public homepage showcase grid
// Dedicated homepage API returning a preview list of available tutors
app.get('/tutors/home', async (req, res) => {
    try {
        console.log("🏠 Homepage component pipeline fetching tutor preview list...");

        // Querying plural 'tutors' table from mediqueue_db
        // LIMIT 6 cuts it down nicely so your homepage showcase stays clean and readable
        const queryStr = 'SELECT * FROM tutors ORDER BY id DESC LIMIT 6';
        const [rows] = await db.execute(queryStr);
        
        console.log(`📊 Transmitting ${rows.length} tutor rows to home dashboard component.`);
        res.send(rows);

    } catch (error) {
        console.error("❌ MySQL Error during home-tutors query processing:", error);
        res.status(500).send({ error: true, message: "Internal data execution system breakdown." });
    }
});
// 2. GET TUTORS BY USER EMAIL (For My Tutors Page)
// Fetch listed tutors filtered by a specific user's email session context
app.get('/my-tutors', async (req, res) => {
    try {
        const { email } = req.query;

        if (!email) {
            console.log("⚠️ /my-tutors hit without an email parameter!");
            return res.status(400).send({ error: true, message: "Email parameter is missing." });
        }

        console.log(`📡 Incoming request for listings belonging to: ${email}`);

        // ⚠️ CHANGE 'email' HERE IF YOUR SQL COLUMN IS NAMED 'tutor_email' or 'user_email'
        const queryStr = 'SELECT * FROM tutors WHERE email = ? ORDER BY id DESC';
        const [rows] = await db.execute(queryStr, [email]);

        console.log(`📦 Database returned ${rows.length} rows for email: ${email}`);
        
        // Let's log a sample row to your terminal so you can see your true column names!
        if (rows.length === 0) {
            const [allTutors] = await db.execute('SELECT * FROM tutors LIMIT 1');
            console.log("🔍 DIAGNOSTIC: Here is what a single row looks like in your database:", allTutors[0]);
        }

        res.send(rows);

    } catch (error) {
        console.error("❌ MySQL error in /my-tutors:", error);
        res.status(500).send({ error: true, message: "Database query crash." });
    }
});
// 3. GET BOOKINGS BY USER EMAIL (For My Bookings Page)
app.get('/my-bookings', async (req, res) => {
    try {
        const email = req.query.email;
        
        if (!email) {
            return res.status(400).send({ error: true, message: "Email query parameter is required." });
        }

        console.log(`🔍 Fetching booking allocations for student email: ${email}`);

        // ⚠️ CRITICAL CHANGE: We select from the 'bookings' table where 'student_email' matches
        const queryStr = 'SELECT * FROM bookings WHERE student_email = ? ORDER BY booked_at DESC';
        const [rows] = await db.execute(queryStr, [email]);
        
        console.log(`📊 Found ${rows.length} booking records for ${email}`);
        
        // Return the clean array rows straight to the frontend dashboard
        res.send(rows);

    } catch (error) {
        console.error("❌ Error fetching my-bookings from database:", error);
        res.status(500).send({ error: true, message: "Failed to load your bookings records matrix." });
    }
});

// 1. Fetch Single Tutor Details by ID
app.get('/tutors/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const [rows] = await db.execute('SELECT * FROM tutors WHERE id = ?', [id]);
        
        if (rows.length === 0) {
            return res.status(404).send({ error: true, message: "Tutor profile data record was not found." });
        }
        
        res.send(rows[0]); // Return the single matching tutor object
    } catch (error) {
        console.error("❌ Error retrieving specific tutor profile:", error);
        res.status(500).send({ error: true, message: "Database lookup failure." });
    }
});

// 2. Submit a New Booking Request & Decrement Tutor Open Slots Automatically
// Endpoint to create a brand new session allocation inside MySQL safely
app.post('/bookings', async (req, res) => {
    try {
        const { tutor_id, tutor_name, photo, subject, price, student_email, tutor_email } = req.body;

        // Validation Fallback: Ensure no critical fields are null/undefined
        if (!tutor_id || !student_email) {
            return res.status(400).send({ 
                error: true, 
                message: "Missing required transactional fields (tutor_id or student_email)." 
            });
        }

        // 1. Check if the tutor exists and has open slots
        const [tutorCheck] = await db.execute('SELECT slots FROM tutors WHERE id = ?', [tutor_id]);
        if (tutorCheck.length === 0) {
            return res.status(404).send({ error: true, message: "Targeted tutor profile record not found." });
        }
        
        if (parseInt(tutorCheck[0].slots) <= 0) {
            return res.status(400).send({ error: true, message: "This session has run out of available registration slots!" });
        }

        // 2. Safe positional bound parameter mapping to matching flat schema definitions
        const insertBookingQuery = `
            INSERT INTO bookings (tutor_id, tutor_name, photo, subject, price, student_email, tutor_email)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        `;
        
        await db.execute(insertBookingQuery, [
            parseInt(tutor_id), 
            tutor_name || 'Unknown Tutor', 
            photo || '', 
            subject || 'General', 
            parseFloat(price || 0), 
            student_email, 
            tutor_email || ''
        ]);

        // 3. Atomically update availability slot decrement counters
        await db.execute('UPDATE tutors SET slots = slots - 1 WHERE id = ?', [tutor_id]);

        console.log(`✅ Session logged successfully for Student: ${student_email}`);
        res.send({ success: true, message: "Booking registered cleanly!" });

    } catch (error) {
        // This will now print the exact line-item SQL issue to your terminal instead of hiding it
        console.error("❌ CRITICAL BOOKINGS CRASH PIPELINE LOG:", error.message);
        res.status(500).send({ 
            error: true, 
            message: `Internal backend engine database error: ${error.message}` 
        });
    }
});

app.delete('/bookings/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // 1. Fetch booking info first to restore the slot back to the tutor profile
        const [bookingRows] = await db.execute('SELECT tutor_id FROM bookings WHERE id = ?', [id]);
        
        if (bookingRows.length === 0) {
            return res.status(404).send({ error: true, message: "Booking record allocation not found." });
        }
        
        const tutorId = bookingRows[0].tutor_id;

        // 2. Clear out the entry from bookings table
        await db.execute('DELETE FROM bookings WHERE id = ?', [id]);
        
        // 3. Increment the open slots parameter inside your tutors table again (+1 slot back)
        await db.execute('UPDATE tutors SET slots = slots + 1 WHERE id = ?', [tutorId]);

        res.send({ success: true, message: "Booking session successfully dropped and room updated." });
    } catch (error) {
        console.error("❌ Error running booking cancellation pipeline:", error);
        res.status(500).send({ error: true, message: "Database backend processing error." });
    }
});
app.put('/tutors/:id', async (req, res) => {
    try {
        const { id } = req.params;
        // Extract exactly what the inline modal form is transmitting
        const { name, photo, subject, price, slots, location } = req.body;

        console.log(`📥 Processing inline profile update for Tutor ID: ${id}`);

        // Safe fallback values to prevent passing 'undefined' to MySQL
        const tutorName = name || null;
        const tutorPhoto = photo || null;
        const tutorSubject = subject || null;
        const tutorPrice = price !== undefined ? parseFloat(price) : 0;
        const tutorSlots = slots !== undefined ? parseInt(slots) : 0;
        const tutorLocation = location || null;

        // SQL Query matching the exact column names in mediqueue_db
        const queryStr = `
            UPDATE tutors 
            SET name = ?, photo = ?, subject = ?, price = ?, slots = ?, location = ?
            WHERE id = ?
        `;

        const [result] = await db.execute(queryStr, [
            tutorName, 
            tutorPhoto, 
            tutorSubject, 
            tutorPrice, 
            tutorSlots, 
            tutorLocation, 
            id
        ]);

        if (result.affectedRows === 0) {
            return res.status(404).send({ error: true, message: "Tutor record not found to apply updates." });
        }

        console.log(`✅ Successfully updated tutor ID: ${id}`);
        res.send({ success: true, message: "Tutor data row updated perfectly!" });

    } catch (error) {
        console.error("❌ MySQL Tutor Profile Update Error:", error);
        res.status(500).send({ error: true, message: "Internal server error applying database changes." });
    }
});

// Secure entry deletion matching primary key id variables
app.delete('/tutors/:id', async (req, res) => {
    try {
        const { id } = req.params;
        console.log(`🗑️ Processing removal request context for Tutor ID: ${id}`);

        // Direct target execution string matching column schema definitions
        const queryStr = 'DELETE FROM tutors WHERE id = ?';
        const [result] = await db.execute(queryStr, [id]);

        // Verifying if rows were actual impacted within mediqueue_db
        if (result.affectedRows === 0) {
            return res.status(404).send({ error: true, message: "Target tutor listing row entry could not be located." });
        }

        console.log(`✅ Cleanly purged listing ID ${id} from database rows.`);
        res.send({ success: true, message: "Listing data index cleared out successfully!" });

    } catch (error) {
        console.error("❌ MySQL Tutor Deletion Operational Error:", error);
        res.status(500).send({ error: true, message: "Internal server structural fault mapping row exclusions." });
    }
});
// Fetch listed tutors filtered by a specific user's email session context
// app.get('/my-tutors', async (req, res) => {
//     try {
//         const { email } = req.query;

//         if (!email) {
//             return res.status(400).send({ error: true, message: "Email query query variable is required." });
//         }

//         console.log(`🔍 Querying custom tutor registry listings created by user: ${email}`);

//         // ✅ CRITICAL SQL MATCH: Querying your plural tutors table filtering by creator email
//         // Adjust "email" here if your database schema uses a different name like "tutor_email" or "user_email"
//         const queryStr = 'SELECT * FROM tutors WHERE email = ? ORDER BY id DESC';
//         const [rows] = await db.execute(queryStr, [email]);

//         console.log(`📦 Found ${rows.length} personal dashboard listings registered under ${email}`);
//         res.send(rows);

//     } catch (error) {
//         console.error("❌ MySQL Error inside /my-tutors route segment:", error);
//         res.status(500).send({ error: true, message: "Internal server data streaming validation breakdown." });
//     }
// });
// Fetch all registered tutors for the public browse catalog page
// ==========================================
// 1. POST: CREATE A NEW TUTOR LISTING LOG
// ==========================================
app.post('/tutors', async (req, res) => {
    try {
        const { 
            name, photo, subject, price, days, time_slot, 
            slots, start_date, institution, location, teaching_mode, email 
        } = req.body;

        if (!email) {
            return res.status(400).send({ error: true, message: "User session email is required." });
        }

        const queryStr = `
            INSERT INTO tutors (
                name, photo, subject, price, days, time_slot, 
                slots, start_date, institution, location, teaching_mode, email
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const [result] = await db.execute(queryStr, [
            name, photo, subject, 
            parseFloat(price || 0), 
            days, time_slot, 
            parseInt(slots || 0), 
            start_date, institution, location, teaching_mode, email
        ]);

        res.send({ success: true, message: "Tutor appended safely!", insertId: result.insertId });
    } catch (error) {
        console.error("❌ MySQL Insertion Error:", error);
        res.status(500).send({ error: true, message: "Internal writing fault error encountered." });
    }
});

// ==========================================
// 2. GET: BROWSE ALL PUBLIC LISTINGS CATALOG
// ==========================================
app.get('/tutors', async (req, res) => {
    try {
        const { search, startDate, endDate } = req.query;
        
        let queryStr = 'SELECT * FROM tutors WHERE 1=1';
        let queryParams = [];

        if (search) {
            queryStr += ' AND (name LIKE ? OR subject LIKE ?)';
            queryParams.push(`%${search}%`, `%${search}%`);
        }
        if (startDate) {
            queryStr += ' AND start_date >= ?';
            queryParams.push(startDate);
        }
        if (endDate) {
            queryStr += ' AND start_date <= ?';
            queryParams.push(endDate);
        }

        queryStr += ' ORDER BY id DESC';

        const [rows] = await db.execute(queryStr, queryParams);
        res.send(rows);
    } catch (error) {
        console.error("❌ MySQL Catalog Loading Error:", error);
        res.status(500).send({ error: true, message: "Failed to stream browse catalog items." });
    }
});