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

/* ================== USER SCHEMA ================== */
const userSchema = new mongoose.Schema(
    {
        username: { type: String, required: true, unique: true },
        password: { type: String, required: true },

        name: String,
        email: String,
        dob: Date,
        gender: String,
        problem: String,

        documents: [String], // Cloudinary URLs
    },
    { timestamps: true }
);

const User = mongoose.model("User", userSchema);

/* ================== MULTER MEMORY STORAGE ================== */
const upload = multer({
    storage: multer.memoryStorage(),
});

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
/* ================== REGISTER ---------- */
app.post("/register", async (req, res) => {
    try {
        const {
            username,
            password,
            name,
            email,
            dob,
            gender,
            problem
        } = req.body;

        // Basic validation
        if (!username || !password) {
            return res.status(400).json({ success: false, message: "Username & password required" });
        }

        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ success: false, message: "User already exists" });
        }

        // Hash password
        const hashedPassword = await argon2.hash(password);

        const newUser = new User({
            username,
            password: hashedPassword,
            name,
            email,
            dob,
            gender,
            problem,
            documents: [] // empty for now
        });

        await newUser.save();

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

        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials",
            });
        }

        const valid = await argon2.verify(user.password, password);
        if (!valid) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials",
            });
        }

        res.json({
            success: true,
            message: "Login successful",
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            success: false,
            message: "Server error",
        });
    }
});

/* ================== SERVER START ================== */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});