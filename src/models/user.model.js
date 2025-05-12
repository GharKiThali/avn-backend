const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  fullname: {
    type: String,
    required: true
  },
  email: {
    type: String,
    required: true,
    unique: true, // Ensures email is unique in the database
  },
  password: {
    type: String,
    required: true
  },
 
  otp: {
    type: String, // To store OTP when sent for verification
    default: ''
  },
  otpExpiration: {
    type: Date,
    required: false, // Date when the OTP expires
  },
  isVerified: {
    type: Boolean,  // Flag to mark if the user has verified their email
    default: false,
  },
}, {
  timestamps: true // Adds createdAt and updatedAt fields
});

const userModel = mongoose.model("users", userSchema);
module.exports = userModel;
