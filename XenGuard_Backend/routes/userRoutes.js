import express from "express";
import { registerUser, loginUser, getUserProfile } from "../controllers/userController.js";

const router = express.Router();

router.post("/register", registerUser);  // Register User
router.post("/login", loginUser);        // Login User
router.get("/:id", getUserProfile);      // Get User Profile

export default router;
