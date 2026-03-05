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
    patientId: { type: String, unique: true, required: true },
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
    docType: String,
    url: String
}, { timestamps: true });

function generatePatientId() {
    const random = Math.floor(10000 + Math.random() * 90000);
    return "PAT" + random;
}

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

        const { email, password, name, dob, gender, problem } = req.body;

        // Basic validation
        if (!password) {
            return res.status(400).json({
                success: false,
                message: "Password required"
            });
        }

        // Hash password
        const hashedPassword = await argon2.hash(password);

        // Generate patient ID
        const patientId = generatePatientId();

        // Create Login record
        const login = await Login.create({
            patientId,
            password: hashedPassword
        });

        // Create UserDetails record
        await UserDetails.create({
            loginId: login._id,
            name,
            email,
            dob,
            gender,
            problem
        });

        // Upload document if provided
        if (req.file) {

            const result = await uploadToCloudinary(req.file.buffer);

            await Documents.create({
                userId: login._id,
                docType: "ID Proof",
                url: result.secure_url
            });
        }

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            patientId: patientId
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

/* ---------- LOGIN ---------- */
app.post("/login", async (req, res) => {

    try {

        const { patientId, password } = req.body;

        if (!patientId || !password) {
            return res.status(400).json({
                success: false,
                message: "Patient ID and password required"
            });
        }

        const login = await Login.findOne({ patientId });

        if (!login) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        const valid = await argon2.verify(login.password, password);

        if (!valid) {
            return res.status(401).json({
                success: false,
                message: "Invalid credentials"
            });
        }

        res.json({
            success: true,
            message: "Login successful",
            patientId: login.patientId
        });

    } catch (err) {

        console.error(err);

        res.status(500).json({
            success: false,
            message: "Server error"
        });
    }
});

/* ================== SERVER START ================== */
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});