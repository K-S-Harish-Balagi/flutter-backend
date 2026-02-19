require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

/* ================== MONGODB CONNECTION ================== */
mongoose.connect(process.env.MONGO_URI)
//mongoose.connect('mongodb://127.0.0.1:27017/flutterLoginDB')
    .then(() => console.log("✅ MongoDB Connected"))
    .catch(err => console.log("❌ DB Connection Error:", err));

mongoose.connection.on("error", err => {
    console.log("MongoDB runtime error:", err);
});

/* ================== USER SCHEMA ================== */

const UserSchema = new mongoose.Schema({
    username: String,
    password: String,
});

const User = mongoose.model('User', UserSchema);

/* ================== ROUTES ================== */

// Create a test user (run once in browser)
app.get('/create', async (req, res) => {
    await User.create({ username: "admin", password: "1234" });
    res.send("User created in DB");
});

// Login check
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username, password });

    if (user) {
        res.json({ success: true });
    } else {
        res.json({ success: false });
    }
});

//register 
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
        const existingUser = await User.findOne({ username });

        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }

        const newUser = new User({ username, password });
        await newUser.save();

        res.json({ success: true, message: "User registered successfully" });
    } catch (err) {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

/* ================== SERVER START ================== */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
});