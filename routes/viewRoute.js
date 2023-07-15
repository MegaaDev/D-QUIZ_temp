const express = require("express");
const router = express.Router();
const viewController = require("./../controllers/viewController");
const authController = require("./../controllers/authController");
const quizController = require("./../controllers/quizController");
router.get(
  "/friendrequest/:recid",
  authController.protect,
  authController.isLogged,
  viewController.sendReq
);
router.get("/", authController.isLogged, viewController.home);
router.get(
  "/createquiz",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.createquiz
);

router.get("/signup", viewController.signup);
router.get("/login", viewController.login);
router.get(
  "/settings",
  authController.relocate,
  authController.isLogged,
  viewController.settings
);
router.get(
  "/myprofile",
  authController.relocate,
  authController.protect,
  viewController.myprofile
);
router.get(
  "/friends",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.friends
);

router.get(
  "/showprofile/:id",
  authController.protect,
  viewController.showprofile
);
router.get("/attemptquiz/:id", viewController.attemptquiz);
router.get("/scorepage/:uid/:qid", viewController.scorepage);
router.get(
  "/incomingrequest",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.incomingrequest
);

router.get(
  "/outgoingrequest",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.outgoingrequest
);
router.get(
  "/acceptedrequest/:recid",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.acceptedrequest
);

router.get(
  "/rejectedrequest/:recid",
  authController.protect,
  authController.isLogged,
  viewController.rejectedrequest
);

router.get(
  "/people",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  viewController.people
);

router.get(
  "/takequiz/:id",
  authController.relocate,
  authController.protect,
  authController.isLogged,
  quizController.takeQuiz,
  viewController.takequiz
);

router.get("/bio", authController.isLogged, viewController.bio);

module.exports = router;
