const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const quizzesTakenSchema = new mongoose.Schema({
  quizID: String,
  score: Number,
  attempted: Number,
  correct: Number,
});

const friendSchema = new mongoose.Schema({
  friendID: String,
  friendName: String,
});

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: [true, "Please enter your name"],
  },
  email: {
    type: String,
    required: [true, "Please enter your email"],
    unique: true,
  },
  username: {
    type: String,
    required: [true, "username required"],
    unique: true,
    minlength: [4, "username must atleast contain 4 characters"],
    maxlength: [20, "username can have atmost 20 characters"],
  },
  password: {
    type: String,
    required: [true, "password required"],
    minlength: [8, "password must contain atleast 8 characters"],
    maxlength: [32, "password can have atmost 32 characters"],
    select: false,
  },
  passwordConfirm: {
    type: String,
    required: [true, "password required"],
    validate: {
      validator: function (el) {
        return el === this.password;
      },
      message: "Please ensure passwordConfirm is same as password",
    },
  },
  bio: {
    type: String,
  },
  tags: {
    type: [String],
  },
  photo: {
    type: String,
    default: "default-photo.png",
  },
  passwordChangedAt: {
    type: Date,
    select: false,
  },
  passwordResetToken: String,
  passwordResetTokenExpiresIn: Date,
  active: {
    type: Boolean,
    default: true,
  },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },

  quizzesTaken: {
    type: [quizzesTakenSchema],
  },

  credits: {
    type: Number,
    default: 0,
  },
  friends: {
    type: [friendSchema],
  },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  this.password = await bcrypt.hash(this.password, 12);
  this.passwordConfirm = undefined;
  next();
});
userSchema.pre("save", async function (next) {
  if (!this.isModified("password") || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000;
  next();
});
// userSchema.pre(/^find/, function (next) {
//   this.find({ active: true });
//   next();
// });

userSchema.methods.checkPasswordCorrect = async function (
  givenPassword,
  userPassword
) {
  return await bcrypt.compare(givenPassword, userPassword);
};

userSchema.methods.checkPasswordChangedAt = async function (JWTissuedTime) {
  if (this.passwordChangedAt) {
    const changedTime = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return changedTime > JWTissuedTime;
  }
  return false;
};

userSchema.methods.createResetToken = function () {
  const createToken = crypto.randomBytes(32).toString("hex");
  this.passwordResetToken = crypto
    .createHash("sha256")
    .update(createToken)
    .digest("hex");
  this.passwordResetTokenExpiresIn = Date.now() + 10 * 60 * 1000;
  return createToken;
};

const User = mongoose.model("User", userSchema);
module.exports = User;
