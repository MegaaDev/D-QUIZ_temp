const User = require("../models/userModel");
const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const crypto = require("crypto");
const sendEmail = require("./../utils/email");
const { decode } = require("querystring");

const createJWTtoken = (id) => {
  return jwt.sign({ id }, process.env.SECRET_FOR_TOKEN, {
    expiresIn: process.env.TOKEN_EXPIRES_IN,
  });
};

const CreateAndSendToken = (user, statusCode, res) => {
  const token = createJWTtoken(user._id);

  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),

    httpOnly: true,
  };

  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;
  res.cookie("jwt", token, cookieOptions);

  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

exports.signUp = async (req, res, next) => {
  try {
    const newUser = await User.create({
      name: req.body.name,
      username: req.body.username,
      email: req.body.email,
      password: req.body.password,
      passwordConfirm: req.body.passwordConfirm,
      bio: req.body.bio,
      tags: req.body.tags,
      photo: req.body.photo,
    });
    CreateAndSendToken(newUser, 200, res);
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};
exports.login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({
        status: "fail",
        message: "Email or Password was not entered!!",
      });
    }

    const user = await User.findOne({ email }).select("+password");

    if (!user || !(await user.checkPasswordCorrect(password, user.password))) {
      console.log("hello");

      return res.status(400).json({
        status: "fail",
        message: "User doesn't exist or Password is incorrect!",
      });
    }
    CreateAndSendToken(user, 200, res);
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.protect = async (req, res, next) => {
  try {
    {
      let token;

      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer")
      ) {
        token = req.headers.authorization.split(" ")[1];
      } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
      }

      // if (!token) {
      //   return res.status(404).json({
      //     status: "fail",
      //     message: "You are not logged in. Log in to get access",
      //   });
      // }

      const decoded = await promisify(jwt.verify)(
        token,
        process.env.SECRET_FOR_TOKEN
      );
      //This checks whether the user is logged in
      const correctUser = await User.findById(decoded.id);
      if (!correctUser) {
        return res.status(404).json({
          status: "fail",
          message: "Account doesn't exist",
        });
      }

      // if (correctUser.checkPasswordChangedAt(decode.iat)) {
      //   return res.status(404).json({
      //     status: "fail",
      //     message: "Password was changed Try to login with new password",
      //   });
      // }
      console.log("hello");

      req.user = correctUser;
      next();
    }
  } catch (err) {
    console.log(err);

    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.relocate = async (req, res, next) => {
  try {
    {
      let token;

      if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer")
      ) {
        token = req.headers.authorization.split(" ")[1];
      } else if (req.cookies.jwt) {
        token = req.cookies.jwt;
      }

      if (!token) {
        return res.redirect("/signup");
      }

      next();
    }
  } catch (err) {
    console.log(err);

    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.isLogged = async (req, res, next) => {
  try {
    let token;

    if (req.cookies.jwt) {
      token = req.cookies.jwt;

      // console.log(req.headers);

      if (!token) {
        return next();
      }

      console.log("megaafromlogged");

      const decoded = await promisify(jwt.verify)(
        req.cookies.jwt,
        process.env.SECRET_FOR_TOKEN
      );

      const freshUser = await User.findById(decoded.id);
      if (!freshUser) {
        return next();
      }

      // if (freshUser.checkPasswordChangedAt(decoded.iat)) {
      //   return next();
      // }

      res.locals.user = freshUser;
      console.log(freshUser.name);

      return next();
    }
  } catch (err) {
    console.log(err);

    return next();
  }

  next();
};

exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });

  res.status(200).json({ status: "success" });
};

exports.restrictTo = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        status: "failure",
        message: "You dont have permission to perform this action",
      });
    }
    next();
  };
};

exports.forgotPassword = async (req, res, next) => {
  const user = await User.findOne({ email: req.body.email });
  if (!user) {
    return res.status(400).json({
      status: "fail",
      message: "User with that email doesn't exist",
    });
  }
  const resetToken = user.createResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `localhost:6000/api/users/resetPassword/${resetToken}`;
  const message = `Forgot your Password? Change your password at ${resetURL}. If you didnt forget your password, please ignore this`;

  try {
    await sendEmail({
      email: req.body.email,
      subject: "Your password reset token (valid for 10 mins)",
      message,
    });
    res.status(200).json({
      status: "success",
      message: "Token sent to email!",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    res.status(500).json({
      status: "fail",
      message: err,
    });
  }
  // res.status(200).json({
  //   status: "success",
  //   message: "hello",
  // });
};
exports.resetPassword = async (req, res) => {
  try {
    const hasedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hasedToken,
      passwordResetTokenExpiresIn: { $gte: Date.now() },
    });

    if (!user) {
      return res.status(404).json({
        status: "failure",
        message: err,
      });
    }
    user.password = req.body.password;
    user.passwordConfirm = req.body.passwordConfirm;

    user.passwordResetToken = undefined;
    user.passwordResetTokenExpiresIn = undefined;

    await user.save();

    CreateAndSendToken(user, 200, res);
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};
