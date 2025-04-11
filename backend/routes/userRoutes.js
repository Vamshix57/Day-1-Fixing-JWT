const express = require("express");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt"); 
const User = require("../models/User");
const { body, validationResult } = require("express-validator");

const router = express.Router();
router.post(
  "/register",
  [
    body("username").isString().notEmpty().withMessage("Username is required"),
    body("password").isString().isLength({ min: 6 }).withMessage("Password must be at least 6 characters long"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }
    const { username, password } = req.body;


    try {
      // Hash the password before saving
      const hashedPassword = await bcrypt.hash(password, 10);
      const user = new User({ username, password: hashedPassword });
      await user.save();
      res.json({ message: "User registered successfully" });
    } catch (err) {
      res.status(500).json({ message: "Error registering user", error: err.message });
    }
  }
);

router.post(
  "/login",
  [
    body("username").isString().notEmpty().withMessage("Username is required"),
    body("password").isString().notEmpty().withMessage("Password is required"),
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const { username, password } = req.body;

    try {
      const user = await User.findOne({ username });
      if (!user) {
        return res.status(400).json({ message: "Invalid username or password" });
      }

      // Compare hashed password
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(400).json({ message: "Invalid username or password" });
      }

      // Generate JWT
      const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRATION });
      res.json({ token });
    } catch (err) {
      res.status(500).json({ message: "Error logging in", error: err.message });
    }
  }
);
module.exports = router;