const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    full_name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },

    role: {
      type: String,
      enum: ["fan", "celebrity", "admin"],
      default: "fan",
    },

    isVerified: {
      type: Boolean,
      default: false,
    },

    emailOtp: String,
    emailOtpExpire: Date,

    resetPasswordToken: String,
    resetPasswordExpire: Date,
  },
  { timestamps: true },
);

// HASH PASSWORD BEFORE SAVE
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;
  this.password = await bcrypt.hash(this.password, 12);
});

// Compare password
userSchema.methods.matchPassword = async function (password) {
  return await bcrypt.compare(password, this.password);
};

// Generate Email OTP
userSchema.methods.generateEmailOTP = function () {
  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  this.emailOtp = crypto.createHash("sha256").update(otp).digest("hex");

  this.emailOtpExpire = Date.now() + 10 * 60 * 1000;

  return otp;
};

// Generate Reset Password Token
userSchema.methods.getResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(20).toString("hex");

  this.resetPasswordToken = crypto
    .createHash("sha256")
    .update(resetToken)
    .digest("hex");

  this.resetPasswordExpire = Date.now() + 10 * 60 * 1000;

  return resetToken;
};

module.exports = mongoose.model("User", userSchema);
