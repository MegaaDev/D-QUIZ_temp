const express = require("express");

const quizController = require("../controllers/quizController");
const authController = require("../controllers/authController");
const userController = require("../controllers/userController");

const router = express.Router();

router.route("/").get(quizController.getAllQuiz);
// router.route("/takequiz").post(authController.protect, quizController.takeQuiz);

router
  .route("/createquiz")
  .post(
    authController.protect,
    authController.isLogged,
    quizController.createQuiz
  );

router
  .route("/submitquiz")
  .post(
    authController.protect,
    authController.isLogged,
    quizController.submitquiz
  );

router
  .route("/:id")
  .get(authController.protect, authController.isLogged, quizController.getQuiz);

module.exports = router;
