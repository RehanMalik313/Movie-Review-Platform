# Movie Review Platform

# Overview

This is a scalable, secure, and feature-rich Movie Review Platform built using Node.js, Express, MongoDB, and Redis. The application supports user authentication, movie reviews, and caching for optimized performance.

# Features

1. User Authentication & Authorization
JWT-based authentication
Role-based access control (Superuser, Member, Visitor)
Google OAuth integration
Email-based OTP verification

2. Movie Management
Fetch movies from TMDB API based on user region
Redis caching for efficient API responses

3. User Reviews
Users can add, read, update, and delete reviews
Role-based restrictions for review modifications

4. Security & Performance Enhancements
Rate limiting to prevent excessive requests
Redis caching for reducing API calls
Clustering to utilize multiple CPU cores
Background processing using Bull queue for email OTPs

# Tech Stack

Backend: Node.js, Express.js
Database: MongoDB (Mongoose ORM)
Cache: Redis
Authentication: JWT, Passport.js (Google OAuth)
Email Services: Nodemailer (SMTP for OTPs)
Job Queue: Bull
Rate Limiting: express-rate-limit
Cluster Management: Node.js Cluster API

# Installation
1, Clone the repository:
```
git clone https://github.com/RehanMalik313/movie-review-platform.git
cd movie-review-platform
```
2, Install dependencies:
```
npm install
```
3, Setup environment variables (.env file):
```
PORT=5001
MONGODB_URI=mongodb://127.0.0.1:27017/movieReviews
REDIS_URL=redis://localhost:6379
JWT_SECRET=your_secret_key
SESSION_SECRET=your_session_secret
EMAIL=your_email@gmail.com
EMAIL_PASS=your_email_password
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
TMDB_API_KEY=your_tmdb_api_key
IPINFO_TOKEN=your_ipinfo_token
```
4, Run the application:
```
npm start
```
# API Endpoints

# Authentication
POST /signup - Register a new user
POST /verify-otp - Verify OTP
POST /login - User login
GET /auth/google - Google SSO

# Movies
GET /movies/:name - Fetch movie details with caching

# Reviews
POST /reviews - Add a movie review
GET /reviews/:movieId - Fetch reviews for a movie
PUT /reviews/:reviewId - Update a review
DELETE /reviews/:reviewId - Delete a review