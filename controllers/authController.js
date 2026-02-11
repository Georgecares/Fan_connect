const User = require("../models/User");
const jwt = require("jsonwebtoken");

const generateToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "7d",
  });
};

// REGISTER
exports.register = async (req, res, next) => {
  try {
    const user = await User.create(req.body);

    res.status(201).json({
      success: true,
      token: generateToken(user._id),
    });
  } catch (error) {
    res.status(400);
    next(error);
  }
};

// LOGIN
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      res.status(401);
      throw new Error("Invalid email or password");
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

// GET CURRENT USER
exports.getMe = async (req, res) => {
  res.status(200).json({
    success: true,
    user: req.user,
  });
};
