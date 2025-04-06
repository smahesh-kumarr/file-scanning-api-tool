import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { body, validationResult } from "express-validator";
import User from "../models/User.js"; 
import config from "../config.js";

const router = express.Router();

// Check for JWT_SECRET
if (!config.jwtSecret) {
  console.error("JWT_SECRET is not defined in environment variables");
  process.exit(1);
}

// User Signup Route
router.post(
  "/signup",
  [
    body("name").notEmpty().withMessage("Name is required"),
    body("email").isEmail().withMessage("Valid email is required"),
    body("password").isLength({ min: 6 }).withMessage("Password must be at least 6 characters"),
  ],
  async (req, res) => {
    try {
      console.log("Received signup request:", { ...req.body, password: '[REDACTED]' });
      
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        console.log("Validation errors:", errors.array());
        return res.status(400).json({ 
          success: false,
          error: errors.array()[0].msg
        });
      }

      const { name, email, password } = req.body;

      // Check if user exists
      let user = await User.findOne({ email });
      if (user) {
        console.log("User already exists:", email);
        return res.status(400).json({ 
          success: false,
          error: "User already exists" 
        });
      }

      // Hash password
      const salt = await bcrypt.genSalt(10);
      const hashedPassword = await bcrypt.hash(password, salt);

      // Create user
      user = new User({
        name,
        email,
        password: hashedPassword
      });

      console.log("Attempting to save user:", { name, email });
      
      // Save user to database
      await user.save();
      
      console.log("User saved successfully:", { name, email });

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id },
        config.jwtSecret,
        { expiresIn: "1h" }
      );

      // Send success response
      res.status(201).json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          }
        }
      });
    } catch (err) {
      console.error("Signup error:", err);
      res.status(500).json({
        success: false,
        error: "Server Error",
        message: err.message
      });
    }
  }
);

// User Login Route
router.post(
  "/login",
  [
    body("email").isEmail().withMessage("Valid email is required"),
    body("password").exists().withMessage("Password is required"),
  ],
  async (req, res) => {
    try {
      console.log("Received login request for email:", req.body.email);
      
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        console.log("Validation errors:", errors.array());
        return res.status(400).json({ 
          success: false,
          error: errors.array()[0].msg
        });
      }

      const { email, password } = req.body;

      // Find user
      const user = await User.findOne({ email });
      if (!user) {
        console.log("User not found:", email);
        return res.status(401).json({
          success: false,
          error: "Invalid credentials"
        });
      }

      // Check password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) {
        console.log("Invalid password for user:", email);
        return res.status(401).json({
          success: false,
          error: "Invalid credentials"
        });
      }

      console.log("Login successful for user:", email);

      // Generate JWT token
      const token = jwt.sign(
        { id: user.id },
        config.jwtSecret,
        { expiresIn: "1h" }
      );

      // Send success response
      res.json({
        success: true,
        data: {
          token,
          user: {
            id: user.id,
            name: user.name,
            email: user.email
          }
        }
      });
    } catch (err) {
      console.error("Login error:", err);
      res.status(500).json({
        success: false,
        error: "Server Error",
        message: err.message
      });
    }
  }
);

export default router;
