const express = require("express");

const authController = require("../controllers/authController");
const userController = require("../controllers/userController");

const router = express.Router();

router.route("/signUp").post(authController.signUp);
router.route("/login").post(authController.login);

router.route("/logout").get(authController.logout);

router.route("/bio").patch(
  authController.protect,

  userController.uploadUserPhoto,
  userController.resizeUserPhoto,
  userController.updateBio
);

router
  .route("/friendrequest/:recid")
  .post(
    authController.protect,
    authController.isLogged,
    userController.sendReq
  );

router.route("/logout").get(authController.logout, userController.searchuser);

router.route("/forgotPassword").post(authController.forgotPassword);
router.route("/resetPassword/:token").patch(authController.resetPassword);

router.route("/").get(userController.getAllUsers);
// router.route("/:id").get(userController.getUser).delete(userController.getUser);

module.exports = router;
