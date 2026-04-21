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
    patientId: { type: String, required: true },
    url: { type: String, required: true },
    docType: { type: String, default: "Report" },
}, { timestamps: true });

// One doc per assignment — therapist can have multiple patients
const assignedSchema = new mongoose.Schema({
    therapistId: { type: String, required: true },
    patientId: { type: String, required: true, unique: true }, // one therapist per patient
}, { timestamps: true });

/* ================== APPOINTMENT SCHEMA ================== */
const appointmentSchema = new mongoose.Schema({
    therapistId: { type: String, required: true },
    patientId: { type: String, required: true },
    date: { type: String, required: true },
    timeSlot: { type: String, required: true },
    status: { type: String, default: "pending" },
}, { timestamps: true });

appointmentSchema.index({ patientId: 1, date: 1 }, { unique: true });
appointmentSchema.index({ therapistId: 1, date: 1, timeSlot: 1 }, { unique: true });

const Appointment = mongoose.model("Appointment", appointmentSchema);

/* ================== MODELS ================== */
const Login = mongoose.model("Login", loginSchema);
const UserDetails = mongoose.model("UserDetails", userSchema);
const Documents = mongoose.model("Documents", documentSchema);
const Therapist = mongoose.model("Therapist", therapistSchema);
const Supervisor = mongoose.model("Supervisor", supervisorSchema);
const Report = mongoose.model("Report", reportSchema);
const Assigned = mongoose.model("Assigned", assignedSchema);

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

        // Auto-assign to a therapist with fewer than 4 patients
        let assignedTherapistId = null;

        const allTherapists = await Therapist.find();

        for (const therapist of allTherapists) {
            const count = await Assigned.countDocuments({
                therapistId: therapist.therapistId,
            });

            if (count < 4) {
                await Assigned.create({
                    therapistId: therapist.therapistId,
                    patientId,
                });
                assignedTherapistId = therapist.therapistId;
                break;
            }
        }

        res.status(201).json({
            success: true,
            message: "User registered successfully",
            patientId,
            assignedTherapistId: assignedTherapistId ?? "No therapist available",
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

/* ---------- SUPERVISOR NAME ---------- */
app.get("/supervisor-name/:supervisorId", authenticateToken, async (req, res) => {
    try {
        const supervisor = await Supervisor.findOne({
            supervisorId: req.params.supervisorId,
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

/* ---------- ASSIGN PATIENT TO THERAPIST ---------- */
// Call via Postman: POST /assign { therapistId, patientId }
app.post("/assign", async (req, res) => {
    try {
        const { therapistId, patientId } = req.body;

        if (!therapistId || !patientId) {
            return res.status(400).json({ success: false, message: "therapistId and patientId required" });
        }

        // Verify both exist
        const therapist = await Therapist.findOne({ therapistId });
        if (!therapist) {
            return res.status(404).json({ success: false, message: "Therapist not found" });
        }

        const patient = await Login.findOne({ patientId });
        if (!patient) {
            return res.status(404).json({ success: false, message: "Patient not found" });
        }

        // Check therapist doesn't already have 4 patients
        const count = await Assigned.countDocuments({ therapistId });
        if (count >= 4) {
            return res.status(400).json({ success: false, message: "Therapist already has 4 patients" });
        }

        // Upsert — if patient already assigned somewhere, reassign
        await Assigned.findOneAndUpdate(
            { patientId },
            { therapistId, patientId },
            { upsert: true, new: true }
        );

        res.json({ success: true, message: "Patient assigned successfully" });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- MY PATIENTS (therapist) ---------- */
app.get("/my-patients", authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== "therapist") {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        const assignments = await Assigned.find({ therapistId: req.user.patientId });

        const patients = await Promise.all(
            assignments.map(async (a) => {
                const login = await Login.findOne({ patientId: a.patientId });
                if (!login) return null;

                const details = await UserDetails.findOne({ loginId: login._id }).select("name");
                return {
                    patientId: a.patientId,
                    name: details?.name ?? a.patientId,
                };
            })
        );

        res.json({
            success: true,
            patients: patients.filter(Boolean), // remove nulls
        });
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

        const { patientId } = req.body;

        if (!patientId) {
            return res.status(400).json({ success: false, message: "Patient ID required" });
        }

        if (!req.file) {
            return res.status(400).json({ success: false, message: "Report file required" });
        }

        // Verify patient is assigned to this therapist
        const assignment = await Assigned.findOne({
            therapistId: req.user.patientId,
            patientId,
        });

        if (!assignment) {
            return res.status(403).json({ success: false, message: "Patient not assigned to you" });
        }

        const therapist = await Therapist.findById(req.user.id);
        if (!therapist) {
            return res.status(404).json({ success: false, message: "Therapist not found" });
        }

        const result = await uploadToCloudinary(req.file.buffer);

        await Report.create({
            therapistId: req.user.patientId,
            supervisorId: therapist.supervisorId,
            patientId,
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

        // Enrich with names
        const enriched = await Promise.all(
            reports.map(async (report) => {
                const obj = report.toObject();

                // Therapist name
                const therapist = await Therapist.findOne({
                    therapistId: report.therapistId,
                }).select("name");
                obj.therapistName = therapist?.name ?? report.therapistId;

                // Patient name
                const login = await Login.findOne({ patientId: report.patientId });
                if (login) {
                    const details = await UserDetails.findOne({
                        loginId: login._id,
                    }).select("name");
                    obj.patientName = details?.name ?? report.patientId;
                } else {
                    obj.patientName = report.patientId;
                }

                return obj;
            })
        );

        res.json({ success: true, reports: enriched });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- MY THERAPIST (patient) ---------- */
app.get("/my-therapist", authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== "patient") {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        const assignment = await Assigned.findOne({ patientId: req.user.patientId });
        if (!assignment) {
            return res.status(404).json({ success: false, message: "No therapist assigned" });
        }

        const therapist = await Therapist.findOne({
            therapistId: assignment.therapistId,
        }).select("name therapistId");

        if (!therapist) {
            return res.status(404).json({ success: false, message: "Therapist not found" });
        }

        res.json({
            success: true,
            therapistId: therapist.therapistId,
            name: therapist.name,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- AVAILABLE SLOTS ---------- */
// GET /available-slots?therapistId=THE12345&date=2025-07-10
app.get("/available-slots", authenticateToken, async (req, res) => {
    try {
        const { therapistId, date } = req.query;

        if (!therapistId || !date) {
            return res.status(400).json({ success: false, message: "therapistId and date required" });
        }

        const ALL_SLOTS = [
            "10:00 AM", "11:00 AM", "12:00 PM",
            "02:00 PM", "03:00 PM",
        ];

        const booked = await Appointment.find({ therapistId, date }).select("timeSlot");
        const bookedSlots = new Set(booked.map((a) => a.timeSlot));

        const available = ALL_SLOTS.filter((s) => !bookedSlots.has(s));

        res.json({ success: true, available });
    } catch (err) {
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- BOOK APPOINTMENT ---------- */
app.post("/appointment", authenticateToken, async (req, res) => {
    try {
        if (req.user.role !== "patient") {
            return res.status(403).json({ success: false, message: "Only patients can book" });
        }

        const { date, timeSlot } = req.body;

        if (!date || !timeSlot) {
            return res.status(400).json({ success: false, message: "date and timeSlot required" });
        }

        // Get assigned therapist
        const assignment = await Assigned.findOne({ patientId: req.user.patientId });
        if (!assignment) {
            return res.status(404).json({ success: false, message: "No therapist assigned" });
        }

        // One appointment per patient per day
        const existingPatient = await Appointment.findOne({
            patientId: req.user.patientId,
            date,
        });
        if (existingPatient) {
            return res.status(409).json({
                success: false,
                message: "You already have an appointment on this day",
            });
        }

        // Slot must still be free for this therapist
        const slotTaken = await Appointment.findOne({
            therapistId: assignment.therapistId,
            date,
            timeSlot,
        });
        if (slotTaken) {
            return res.status(409).json({
                success: false,
                message: "This slot is no longer available",
            });
        }

        const appt = await Appointment.create({
            therapistId: assignment.therapistId,
            patientId: req.user.patientId,
            date,
            timeSlot,
        });

        res.status(201).json({ success: true, message: "Appointment booked", appointment: appt });
    } catch (err) {
        if (err.code === 11000) {
            return res.status(409).json({ success: false, message: "Slot conflict, please pick another" });
        }
        console.error(err);
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ---------- GET APPOINTMENTS ---------- */
// Patient → own appointments. Therapist → all their appointments.
app.get("/appointments", authenticateToken, async (req, res) => {
    try {
        let query = {};

        if (req.user.role === "patient") {
            query.patientId = req.user.patientId;
        } else if (req.user.role === "therapist") {
            query.therapistId = req.user.patientId;
        } else {
            return res.status(403).json({ success: false, message: "Access denied" });
        }

        const appointments = await Appointment.find(query).sort({ date: 1, timeSlot: 1 });

        // Enrich patient name for therapist view
        const enriched = await Promise.all(
            appointments.map(async (appt) => {
                const obj = appt.toObject();
                if (req.user.role === "therapist") {
                    const login = await Login.findOne({ patientId: appt.patientId });
                    if (login) {
                        const details = await UserDetails.findOne({ loginId: login._id }).select("name");
                        obj.patientName = details?.name ?? appt.patientId;
                    } else {
                        obj.patientName = appt.patientId;
                    }
                }
                return obj;
            })
        );

        res.json({ success: true, appointments: enriched });
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