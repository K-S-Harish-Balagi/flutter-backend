/* ================== DNS FIX ================== */
const dns = require("dns");
dns.setServers(["8.8.8.8"]);

/* ================== IMPORTS ================== */
require("dotenv").config();
const jwt = require("jsonwebtoken");
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const argon2 = require("argon2");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");
const { customAlphabet } = require("nanoid");
const numericId = customAlphabet("0123456789", 5);

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

/* ================== ID GENERATORS ================== */
function generatePatientId() { return "PAT" + numericId(); }
function generateTherapistId() { return "THE" + numericId(); }
function generateSupervisorId() { return "SUP" + numericId(); }

/* ================== SCHEMAS ================== */

const loginSchema = new mongoose.Schema({
    patientId: { type: String, unique: true, required: true },
    password: { type: String, required: true },
}, { timestamps: true });

const userSchema = new mongoose.Schema({
    loginId: { type: mongoose.Schema.Types.ObjectId, ref: "Login", required: true },
    name: String,
    email: String,
    dob: Date,
    gender: String,
    problem: String,
}, { timestamps: true });

const documentSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: "Login", required: true },
    docType: String,
    url: String,
}, { timestamps: true });

const therapistSchema = new mongoose.Schema({
    therapistId: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    name: String,
    supervisorId: { type: String, required: true },
}, { timestamps: true });

const supervisorSchema = new mongoose.Schema({
    supervisorId: { type: String, unique: true, required: true },
    password: { type: String, required: true },
    name: String,
}, { timestamps: true });

const reportSchema = new mongoose.Schema({
    therapistId: { type: String, required: true },
    supervisorId: { type: String, required: true },
    url: { type: String, required: true },
    docType: { type: String, default: "Report" },
}, { timestamps: true });

/* ================== MODELS ================== */
const Login = mongoose.model("Login", loginSchema);
const UserDetails = mongoose.model("UserDetails", userSchema);
const Documents = mongoose.model("Documents", documentSchema);
const Therapist = mongoose.model("Therapist", therapistSchema);
const Supervisor = mongoose.model("Supervisor", supervisorSchema);
const Report = mongoose.model("Report", reportSchema);

/* ================== MULTER ================== */
const upload = multer({ storage: multer.memoryStorage() });

/* ================== CLOUDINARY HELPER ================== */
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

/* ================== AUTH MIDDLEWARE ================== */
function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (!token) {
        return res.status(401).json({ success: false, message: "Token required" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ success: false, message: "Invalid token" });
        }
        req.user = user;
        next();
    });
}

/* ================== ROUTES ================== */

/* ---------- PATIENT REGISTER ---------- */
app.post("/register", upload.single("idDoc"), async (req, res) => {
    try {
        const { email, password, name, dob, gender, problem } = req.body;
        if (!password) {
            return res.status(400).json({ success: false, message: "Password required" });
        }

        const hashedPassword = await argon2.hash(password);
        const patientId = generatePatientId();
        const login = await Login.create({ patientId, password: hashedPassword });

        await UserDetails.create({ loginId: login._id, name, email, dob, gender, problem });

        if (req.file) {
            const result = await uploadToCloudinary(req.file.buffer);
            await Documents.create({
                userId: login._id,
                docType: "ID Proof",
                url: result.secure_url,
            });
        }

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            patientId,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- PATIENT LOGIN ---------- */
app.post("/login", async (req, res) => {
    try {
        const { patientId, password } = req.body;

        if (!patientId || !password) {
            return res.status(400).json({ success: false, message: "Patient ID and password required" });
        }

        const login = await Login.findOne({ patientId });
        if (!login) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const valid = await argon2.verify(login.password, password);
        if (!valid) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: login._id, patientId: login.patientId, role: "patient" },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful",
            patientId: login.patientId,
            role: "patient",
            token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- THERAPIST LOGIN ---------- */
app.post("/therapist-login", async (req, res) => {
    try {
        const { patientId, password } = req.body;

        if (!patientId || !password) {
            return res.status(400).json({ success: false, message: "Therapist ID and password required" });
        }

        const therapist = await Therapist.findOne({ therapistId: patientId });
        if (!therapist) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const valid = await argon2.verify(therapist.password, password);
        if (!valid) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: therapist._id, patientId: therapist.therapistId, role: "therapist" },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful",
            patientId: therapist.therapistId,
            role: "therapist",
            token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- SUPERVISOR LOGIN ---------- */
app.post("/supervisor-login", async (req, res) => {
    try {
        const { patientId, password } = req.body;

        if (!patientId || !password) {
            return res.status(400).json({ success: false, message: "Supervisor ID and password required" });
        }

        const supervisor = await Supervisor.findOne({ supervisorId: patientId });
        if (!supervisor) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const valid = await argon2.verify(supervisor.password, password);
        if (!valid) {
            return res.status(401).json({ success: false, message: "Invalid credentials" });
        }

        const token = jwt.sign(
            { id: supervisor._id, patientId: supervisor.supervisorId, role: "supervisor" },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.json({
            success: true,
            message: "Login successful",
            patientId: supervisor.supervisorId,
            role: "supervisor",
            token,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- SUPERVISOR NAME ---------- */
app.get("/supervisor-name/:supervisorId", authenticateToken, async (req, res) => {
    try {
        const supervisor = await Supervisor.findOne({
            supervisorId: req.params.supervisorId
        }).select("name supervisorId");

        if (!supervisor) {
            return res.status(404).json({ success: false, message: "Supervisor not found" });
        }

        res.json({ success: true, name: supervisor.name, supervisorId: supervisor.supervisorId });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});


/* ---------- PATIENT PROFILE ---------- */
app.get("/profile", authenticateToken, async (req, res) => {
    try {
        const profile = await UserDetails.findOne({ loginId: req.user.id });
        const docs = await Documents.find({ userId: req.user.id });
        res.json({ success: true, profile, documents: docs });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- THERAPIST ME ---------- */
app.get("/therapist-me", authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== "therapist") {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        const therapist = await Therapist.findById(req.user.id).select("-password");
        if (!therapist) {
            return res.status(404).json({ success: false, message: "Therapist not found" });
        }

        res.json({ success: true, therapist });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- SEND REPORT ---------- */
app.post("/send-report", authenticateToken, upload.single("report"), async (req, res) => {
    try {
        if (req.user.role !== "therapist") {
            return res.status(403).json({ success: false, message: "Only therapists can send reports" });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: "Report file required" });
        }

        const therapist = await Therapist.findById(req.user.id);
        if (!therapist) {
            return res.status(404).json({ success: false, message: "Therapist not found" });
        }

        const result = await uploadToCloudinary(req.file.buffer);

        await Report.create({
            therapistId: req.user.patientId,
            supervisorId: therapist.supervisorId,
            url: result.secure_url,
            docType: req.file.mimetype.includes("pdf") ? "PDF" : "Image",
        });

        res.json({ success: true, message: "Report sent successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- GET REPORTS ---------- */
app.get("/get-reports", authenticateToken, async (req, res) => {
    try {
        let reports;

        if (req.user.role === "therapist") {
            reports = await Report.find({ therapistId: req.user.patientId }).sort({ createdAt: -1 });
        } else if (req.user.role === "supervisor") {
            reports = await Report.find().sort({ createdAt: -1 });
        } else {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        res.json({ success: true, reports });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ================== SERVER START ================== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});