const User = require("../models/User");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

/////////////////////////////////////////////////////
// REGISTER - Send OTP
/////////////////////////////////////////////////////
exports.register = async (req, res, next) => {
  try {
    const user = await User.create(req.body);

    const otp = user.generateEmailOTP();
    await user.save({ validateBeforeSave: false });

    await sendEmail({
      email: user.email,
      subject: "Email Verification OTP",
      message: `Your OTP is: ${otp}`,
    });

    res.status(200).json({
      success: true,
      message: "OTP sent to email",
    });
  } catch (error) {
    next(error);
  }
};

/////////////////////////////////////////////////////
// VERIFY EMAIL
/////////////////////////////////////////////////////
exports.verifyEmail = async (req, res, next) => {
  try {
    const { email, otp } = req.body;

    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    const user = await User.findOne({
      email,
      emailOtp: hashedOtp,
      emailOtpExpire: { $gt: Date.now() },
    });

    if (!user) {
      res.status(400);
      throw new Error("Invalid or expired OTP");
    }

    user.isVerified = true;
    user.emailOtp = undefined;
    user.emailOtpExpire = undefined;

    await user.save();

    res.status(200).json({
      success: true,
      token: generateToken(user._id),
    });
  } catch (error) {
    next(error);
  }
};

/////////////////////////////////////////////////////
// LOGIN
/////////////////////////////////////////////////////
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      res.status(401);
      throw new Error("Invalid email or password");
    }

    if (!user.isVerified) {
      res.status(401);
      throw new Error("Please verify your email first");
    }

    const isMatch = await user.matchPassword(password);

    if (!isMatch) {
      res.status(401);
      throw new Error("Invalid email or password");
    }

    res.status(200).json({
      success: true,
      token: generateToken(user._id),
    });
  } catch (error) {
    next(error);
  }
};

/////////////////////////////////////////////////////
// FORGOT PASSWORD - Send OTP
/////////////////////////////////////////////////////
exports.forgotPassword = async (req, res, next) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      res.status(404);
      throw new Error("User not found");
    }

    const otp = user.generateEmailOTP();
    await user.save({ validateBeforeSave: false });

    await sendEmail({
      email: user.email,
      subject: "Password Reset OTP",
      message: `Your OTP for password reset is: ${otp}`,
    });

    res.status(200).json({
      success: true,
      message: "OTP sent to email",
    });
  } catch (error) {
    next(error);
  }
};

/////////////////////////////////////////////////////
// RESET PASSWORD
/////////////////////////////////////////////////////
exports.resetPassword = async (req, res, next) => {
  try {
    const { email, otp, newPassword } = req.body;

    const hashedOtp = crypto.createHash("sha256").update(otp).digest("hex");

    const user = await User.findOne({
      email,
      emailOtp: hashedOtp,
      emailOtpExpire: { $gt: Date.now() },
    }).select("+password");

    if (!user) {
      res.status(400);
      throw new Error("Invalid or expired OTP");
    }

    user.password = newPassword;
    user.emailOtp = undefined;
    user.emailOtpExpire = undefined;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (error) {
    next(error);
  }
};

/////////////////////////////////////////////////////
// GET CURRENT USER
/////////////////////////////////////////////////////
exports.getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};
