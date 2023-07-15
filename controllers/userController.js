const User = require("./../models/userModel");
const Friend = require("./../models/friendModel");

const multer = require("multer");
const sharp = require("sharp");
// const multerStorage = multer.diskStorage({
//   destination: (req, file, cb) => {
//     cb(null, "public/img/users");
//   },
//   filename: (req, file, cb) => {
//     const ext = file.mimetype.split("/")[1];
//     cb(null, `user-${req.user.id}-${Date.now()}.${ext}`);
//   },
// });

const multerStorage = multer.memoryStorage();
const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith("image")) {
    cb(null, true);
  } else {
    cb(
      res.status(400).json({
        status: "failure",
        message: "Upload only image file",
      }),
      false
    );
  }
};
const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});

exports.uploadUserPhoto = upload.single("photo");

exports.resizeUserPhoto = (req, res, next) => {
  if (!req.file) {
    console.log("hellossssoo");
    return next();
  }
  console.log("hellooo");

  req.file.filename = `user-${req.user.id}-${Date.now()}.jpeg`;
  console.log(req.file.filename);

  sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat("jpeg")
    .jpeg({ quality: 90 })
    .toFile(`./public/img/users/${req.file.filename}`);
  next();
};

const ObjFilter = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};

exports.getAllUsers = async (req, res) => {
  try {
    let userQuery = User.find();
    let filter = {};
    if (req.query.username) {
      filter = req.query.username;
      userQuery = userQuery.find({
        username: { $regex: filter, $options: "i" },
      });
    }
    const users = await userQuery;
    res.status(200).json({
      status: "success",
      users,
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.getUser = async (req, res) => {
  try {
    const users = await User.find({ _id: req.params.id });

    res.status(200).json({
      status: "success",
      users,
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.deleteMe = async (req, res) => {
  try {
    await User.findByIdAndUpdate({ _id: req.params.id }, { active: false });
    res.status(200).json({
      status: "success",
      message: null,
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.updateBio = async (req, res, next) => {
  try {
    const filteredObj = ObjFilter(req.body, "bio", "tags", "photo");
    if (req.file) filteredObj.photo = req.file.filename;
    const updatedUser = await User.findByIdAndUpdate(req.user.id, filteredObj, {
      new: true,
      runValidators: true,
    });

    res.status(200).json({
      status: "success",
      data: {
        user: updatedUser,
      },
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};
exports.searchuser = async (req, res) => {
  try {
    let userQuery = User.find();
    let filter = {};
    if (req.query.username) {
      filter = req.query.username;
      userQuery = userQuery.find({
        username: { $regex: filter, $options: "i" },
      });
    }
    const users = await userQuery;
    res.status(200).json({
      status: "success",
      users,
    });
  } catch (err) {
    res.status(404).json({
      status: "fail",
      message: err,
    });
  }
};

exports.sendReq = async (req, res) => {
  try {
    const requester = req.user.id;
    const reciever = req.params.recid;
    console.log("code reached!!!!!");

    const friends = await Friend.find();
    let bool_temp = true;
    for (let i = 0; i < friends.length; i++) {
      if (
        friends[i].reciever == requester &&
        friends[i].requester == reciever
      ) {
        bool_temp = false;
        break;
      }
    }
    let friendRequest;
    if (bool_temp) {
      friendRequest = await Friend.create({
        requester: requester,
        reciever: reciever,
        status: 1,
      });

      res.status(200).json({
        status: "success",
        friendRequest,
      });
    } else {
      res.status(404).json({
        status: "error",
        message: "The User has already sent you a friend Request",
      });
    }
  } catch (err) {
    res.status(404).json({
      status: "error",
      message: err,
    });
  }
};
