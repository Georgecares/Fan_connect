const express = require("express");
const router = express.Router();

const {
  register,
  login,
  getMe,
  verifyEmail,
  forgotPassword,
  resetPassword,
} = require("../controllers/authController");

const { protect } = require("../middleware/authMiddleware");

router.post("/register", register);
router.post("/verify-email", verifyEmail);
router.post("/login", login);
router.post("/forgot-password", forgotPassword);
router.post("/reset-password", resetPassword);

router.get("/me", protect, getMe);

module.exports = router;
