const express = require('express');
const axios = require('axios');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const nodemailer = require('nodemailer');
const passport = require('passport');
const session = require('express-session');
const redis = require('redis');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const requestIp = require('request-ip');
const cluster = require('cluster');
const os = require('os');
const rateLimit = require('express-rate-limit');
const Queue = require('bull');
require('dotenv').config();

// Clustering
if (cluster.isMaster) {
    const numCPUs = os.cpus().length;
    console.log(`Master ${process.pid} is running`);

    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
        cluster.fork(); // Restart the worker
    });
} else {
    const app = express();
    const PORT = process.env.PORT || 5001;

    // Middleware
    app.set('trust proxy', true);
    app.use(express.json());
    app.use(requestIp.mw());
    app.use(session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: { secure: false }
    }));
    app.use(passport.initialize());
    app.use(passport.session());

    // Rate Limiting
    const limiter = rateLimit({
        windowMs: 15 * 60 * 1000, // 15 minutes
        max: 100 // Limit each IP to 100 requests per windowMs
    });
    app.use(limiter);

    // MongoDB Connection
    mongoose.connect(process.env.MONGODB_URI || "mongodb://127.0.0.1:27017/movieReviews", {
        useNewUrlParser: true,
        useUnifiedTopology: true,
        poolSize: 10 // Connection pool size
    })
        .then(() => console.log("Connected to MongoDB"))
        .catch(err => console.error("MongoDB Connection Error:", err));

    // Redis Client
    const client = redis.createClient({
        url: process.env.REDIS_URL || 'redis://localhost:6379',
        socket: {
            reconnectStrategy: (retries) => Math.min(retries * 50, 2000)
        }
    });
    client.on("connect", () => {
        console.log("Connected to Redis");
    });
    client.on("error", (err) => console.error("Redis Error:", err));
    client.connect();

    // Movie Schema
    const movieSchema = new mongoose.Schema({
        title: { type: String, unique: true, required: true, index: true },
        description: String,
        genre: String,
        releaseYear: Number,
        rating: Number
    });
    const Movie = mongoose.model("Movie", movieSchema);

    // User Schema
    const userSchema = new mongoose.Schema({
        username: String,
        email: { type: String, unique: true, index: true },
        password: String,
        otp: String,
        otpExpiresAt: Date,
        verified: { type: Boolean, default: false },
        role: { type: String, enum: ['superuser', 'member', 'visitor'], default: 'visitor' }
    });

    userSchema.index({ email: 1 }, { unique: true });
    const User = mongoose.model("User", userSchema);

    // Review Schema
    const reviewSchema = new mongoose.Schema({
        movieId: String,
        rating: Number,
        text: String,
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
    }, { timestamps: true });
    const Review = mongoose.model("Review", reviewSchema);

    // JWT Token Generation
    const generateToken = (user) => {
        return jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
    };

    // Email Transporter
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL,
            pass: process.env.EMAIL_PASS
        }
    });

    const sendOTP = async (email, otp) => {
        try {
            await transporter.sendMail({
                from: process.env.EMAIL,
                to: email,
                subject: "Your OTP Code",
                text: `Your OTP code is ${otp}`
            });
            console.log(`OTP sent to ${email}`);
        } catch (error) {
            console.error("Error sending OTP:", error);
        }
    };

    // Background Worker for Emails
    const emailQueue = new Queue('emailQueue', {
        redis: {
            host: 'localhost',
            port: 6379
        }
    });

    emailQueue.process(async (job) => {
        const { email, otp } = job.data;
        await sendOTP(email, otp);
    });

    // Routes
    app.get("/", (req, res) => {
        res.send("Welcome to the Movie Review Platform 🎬");
    });

    // Signup Route
    app.post("/signup", async (req, res) => {
        try {
            const { username, email, password, role } = req.body;
            const existingUser = await User.findOne({ email });
            if (existingUser) return res.status(400).json({ error: "Email already registered" });

            const hashedPassword = await bcrypt.hash(password, 10);
            const otp = Math.floor(100000 + Math.random() * 900000).toString();

            const isFirstUser = (await User.countDocuments()) === 0;
            const userRole = isFirstUser ? 'superuser' : role || 'visitor';

            const newUser = new User({ username, email, password: hashedPassword, otp, role: userRole });
            await newUser.save();

            await emailQueue.add({ email, otp });

            res.json({ message: "User registered. Verify OTP.", role: userRole });
        } catch (error) {
            console.error("Signup error:", error);
            res.status(500).json({ error: "Internal Server Error" });
        }
    });

    // OTP Verification
    app.post("/verify-otp", async (req, res) => {
        try {
            const { email, otp } = req.body;
            const user = await User.findOne({ email });

            if (!user || user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });

            if (user.otpExpiresAt && user.otpExpiresAt < Date.now()) {
                return res.status(400).json({ error: "OTP expired. Request a new one." });
            }

            user.verified = true;
            user.otp = null;
            user.otpExpiresAt = null;
            await user.save();

            res.json({ message: "OTP verified successfully" });
        } catch (error) {
            console.error("OTP Verification error:", error);
            res.status(500).json({ error: "Internal Server Error" });
        }
    });

    // Login Route
    app.post("/login", async (req, res) => {
        try {
            const { email, password } = req.body;
            const user = await User.findOne({ email });

            if (!user || !(await bcrypt.compare(password, user.password))) {
                return res.status(400).json({ error: "Invalid credentials" });
            }
            if (!user.verified) return res.status(400).json({ error: "Verify OTP first" });

            const token = generateToken(user);
            res.json({ message: "Login successful", token });
        } catch (error) {
            console.error("Login error:", error);
            res.status(500).json({ error: "Internal Server Error" });
        }
    });

    // Google SSO
    passport.use(new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/auth/google/callback"
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            let user = await User.findOne({ email: profile.emails[0].value });
            if (!user) {
                user = new User({
                    username: profile.displayName,
                    email: profile.emails[0].value,
                    verified: true
                });
                await user.save();
            }
            return done(null, user);
        } catch (error) {
            return done(error, null);
        }
    }));

    passport.serializeUser((user, done) => done(null, user.id));
    passport.deserializeUser(async (id, done) => {
        const user = await User.findById(id);
        done(null, user);
    });

    app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
    app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }),
        (req, res) => {
            const token = generateToken(req.user);
            res.json({ message: "Login successful", token });
        }
    );

    // Auth Middleware
    const authMiddleware = (req, res, next) => {
        const token = req.headers['authorization'];
        if (!token) return res.status(401).json({ error: "Authentication required" });

        jwt.verify(token.replace("Bearer ", ""), process.env.JWT_SECRET, async (err, decoded) => {
            if (err) return res.status(403).json({ error: "Invalid token" });

            const user = await User.findById(decoded.id);
            if (!user) return res.status(403).json({ error: "User not found" });

            req.user = user;
            next();
        });
    };

    // Role-Based Access Control Middleware
    const authorizeRoles = (...roles) => (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                error: `Access denied: Your role: ${req.user.role}`
            });
        }
        next();
    };

    // Ban and Unban User
    app.put("/users/:userId/ban", authMiddleware, authorizeRoles('superuser'), async (req, res) => {
        try {
            const user = await User.findById(req.params.userId);
            if (!user) return res.status(404).json({ error: "User not found" });

            if (!user.verified) return res.status(400).json({ error: "User is already banned" });

            user.verified = false;
            await user.save();

            res.json({ message: `User ${user.username} has been banned` });
        } catch (error) {
            console.error("Error banning user:", error);
            res.status(500).json({ error: "Failed to ban user" });
        }
    });

    app.put("/users/:userId/unban", authMiddleware, authorizeRoles('superuser'), async (req, res) => {
        try {
            const user = await User.findById(req.params.userId);
            if (!user) return res.status(404).json({ error: "User not found" });

            if (user.verified) return res.status(400).json({ error: "User is already active" });

            user.verified = true;
            await user.save();

            res.json({ message: `User ${user.username} has been unbanned` });
        } catch (error) {
            console.error("Error unbanning user:", error);
            res.status(500).json({ error: "Failed to unban user" });
        }
    });

    // Fetch Movie by Name with Redis Caching
    app.get("/movies/:name", async (req, res) => {
        const movieName = req.params.name;
    
        // Get user IP
        const clientIp = req.clientIp || req.headers["x-forwarded-for"] || req.ip;
        console.log("Detected IP:", clientIp);
    
        try {
            // Get region based on IP
            const regionResponse = await axios.get(`https://ipinfo.io/${clientIp}/json?token=${process.env.IPINFO_TOKEN}`);
            console.log("IPinfo API Response:", regionResponse.data);
    
            const region = regionResponse.data.region || "US"; // Default region
            console.log("Detected Region:", region);
    
            // Sanitize movie name and region for Redis key
            const sanitizeKey = (str) => str.replace(/\s+/g, '_').toLowerCase();
            const cacheKey = `movie:${sanitizeKey(movieName)}:${sanitizeKey(region)}`;
            console.log("Cache Key:", cacheKey);
    
            // Ensure Redis client is connected
            if (!client.isOpen) {
                await client.connect();
            }
    
            // Check Redis cache
            const cachedData = await client.get(cacheKey);
            if (cachedData) {
                console.log("Serving from cache");
                return res.json(JSON.parse(cachedData));
            }
    
            // Fetch movie data from TMDB API
            const response = await axios.get("https://api.themoviedb.org/3/search/movie", {
                headers: { Authorization: `Bearer ${process.env.TMDB_API_KEY}` },
                params: { query: movieName, region: region },
            });
    
            console.log("TMDB API Response:", response.data);
    
            if (!response.data) {
                throw new Error("Invalid data received from TMDB API");
            }
    
            // Store in Redis with 1-hour expiration
            await client.set(cacheKey, JSON.stringify(response.data), 'EX', 3600);
            console.log("Data cached in Redis");
    
            res.json(response.data);
        } catch (error) {
            console.error("Error fetching movie details:", error);
            res.status(500).json({ error: "Failed to fetch movie details" });
        }
    });
    
    // Review Routes (Post/create Review)
    app.post("/reviews", authMiddleware, authorizeRoles('member', 'superuser'), async (req, res) => {
        try {
            if (!req.user.verified) {
                return res.status(403).json({ error: "Verify your account before adding reviews" });
            }

            const { movieId, rating, text } = req.body;
            if (!movieId || !rating || !text) {
                return res.status(400).json({ error: "All fields (movieId, rating, text) are required" });
            }

            const newReview = new Review({ movieId, rating, text, userId: req.user._id });
            await newReview.save();

            res.status(201).json({ message: "Review added successfully", review: newReview });
        } catch (error) {
            console.error("Error adding review:", error);
            res.status(500).json({ error: "Failed to add review" });
        }
    });
    //Read Reviews
    app.get("/reviews/:movieId", async (req, res) => {
        try {
            const movieId = req.params.movieId;
            const reviews = await Review.find({ movieId }).sort({ createdAt: -1 });

            res.json(reviews);
        } catch (error) {
            console.error("Error fetching reviews:", error);
            res.status(500).json({ error: "Failed to fetch reviews" });
        }
    });
    //Update Reviews
    app.put("/reviews/:reviewId", authMiddleware, authorizeRoles('member', 'superuser'), async (req, res) => {
        try {
            const { rating, text } = req.body;
            const reviewId = req.params.reviewId;

            const review = await Review.findById(reviewId);
            if (!review) return res.status(404).json({ error: "Review not found" });

            if (req.user.role !== 'superuser' && review.userId.toString() !== req.user._id.toString()) {
                return res.status(403).json({ error: "You can only edit your own reviews" });
            }

            review.rating = rating;
            review.text = text;
            await review.save();

            res.json({ message: "Review updated successfully", review });
        } catch (error) {
            console.error("Error updating review:", error);
            res.status(500).json({ error: "Failed to update review" });
        }
    });
    //Delete Reviews
    app.delete("/reviews/:reviewId", authMiddleware, authorizeRoles('member', 'superuser'), async (req, res) => {
        try {
            const reviewId = req.params.reviewId;
            const review = await Review.findById(reviewId);
            if (!review) return res.status(404).json({ error: "Review not found" });

            if (req.user.role !== 'superuser' && review.userId.toString() !== req.user._id.toString()) {
                return res.status(403).json({ error: "You can only delete your own reviews" });
            }

            await review.deleteOne();
            res.json({ message: "Review deleted successfully" });
        } catch (error) {
            console.error("Error deleting review:", error);
            res.status(500).json({ error: "Failed to delete review" });
        }
    });

    // Start Server
    app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT} on worker ${process.pid}`);
    });
}