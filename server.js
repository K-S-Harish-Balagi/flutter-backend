/* ================== DNS FIX ================== */
const dns = require("dns");
dns.setServers(["8.8.8.8"]);

/* ================== IMPORTS ================== */
require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const argon2 = require("argon2");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");

const app = express();

/* ================== MIDDLEWARE ================== */
app.use(cors());
app.use(express.json());

/* ================== CLOUDINARY CONFIG ================== */
cloudinary.config({
    cloud_name: process.env.CLOUD_NAME,
    api_key: process.env.API_KEY,
    api_secret: process.env.API_SECRET,
});

/* ================== MONGODB CONNECTION ================== */
mongoose
    .connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB Connected"))
    .catch((err) => console.error("❌ DB Connection Error:", err));

mongoose.connection.on("error", (err) => {
    console.error("MongoDB runtime error:", err);
});

/* ================== SCHEMAS ================== */
// Login table
const loginSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
}, { timestamps: true });

// User details table
const userSchema = new mongoose.Schema({
    loginId: { type: mongoose.Schema.Types.ObjectId, ref: 'Login', required: true },
    name: String,
    email: String,
    dob: Date,
    gender: String,
    problem: String
}, { timestamps: true });

// Documents table
const documentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'Login', required: true },
    docType: String, // e.g., "ID Proof"
    url: String
}, { timestamps: true });

const Login = mongoose.model("Login", loginSchema);
const UserDetails = mongoose.model("UserDetails", userSchema);
const Documents = mongoose.model("Documents", documentSchema);

/* ================== MULTER MEMORY STORAGE ================== */
const upload = multer({ storage: multer.memoryStorage() });

/* ================== CLOUDINARY UPLOAD HELPER ================== */
const uploadToCloudinary = (buffer) => {
    return new Promise((resolve, reject) => {
        const stream = cloudinary.uploader.upload_stream(
            { resource_type: "auto" },
            (error, result) => {
                if (error) reject(error);
                else resolve(result);
            }
        );
        streamifier.createReadStream(buffer).pipe(stream);
    });
};

/* ================== ROUTES ================== */

/* ---------- REGISTER ---------- */
app.post("/register", upload.single("idDoc"), async (req, res) => {
    try {
        const { username, password, name, email, dob, gender, problem } = req.body;
        username = email;
        // 1️⃣ Basic validation
        if (!username || !password) {
            return res.status(400).json({ success: false, message: "Username & password required" });
        }

        const existingUser = await Login.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ success: false, message: "User already exists" });
        }

        // 2️⃣ Create Login record (hash password)
        const hashedPassword = await argon2.hash(password);
        const login = await Login.create({ username, password: hashedPassword });

        // 3️⃣ Create UserDetails record
        await UserDetails.create({
            loginId: login._id,
            name,
            email,
            dob,
            gender,
            problem
        });

        // 4️⃣ Upload document if provided
        if (req.file) {
            const result = await uploadToCloudinary(req.file.buffer);
            await Documents.create({
                userId: login._id,
                docType: "ID Proof",
                url: result.secure_url
            });
        }

        res.status(201).json({ success: true, message: "User registered successfully" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {
    try {
        const { username, password } = req.body;

        const login = await Login.findOne({ username });
        if (!login) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const valid = await argon2.verify(login.password, password);
        if (!valid) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        res.json({ success: true, message: "Login successful" });

    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ================== SERVER START ================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));