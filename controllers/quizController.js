const User = require("../models/userModel");
const Quiz = require("./../models/quizModel");

exports.getAllQuiz = async (req, res) => {
  try {
    const quiz = await Quiz.find().select("title difficulty");
    console.log(req.user);

    res.status(200).json({
      status: "success",
      data: {
        quiz,
      },
    });
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};

exports.createQuiz = async (req, res) => {
  try {
    req.body.userID = req.user.id;
    req.body.username = req.user.username;

    const newQuiz = await Quiz.create(req.body);

    res.status(200).json({
      status: "success",
      newQuiz,
    });
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};

exports.getQuiz = async (req, res) => {
  try {
    const id = req.user.id;
    const quiz = await Quiz.findById(id);
    res.status(200).json({
      status: "success",
      data: {
        quiz,
      },
    });
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};

exports.takeQuiz = async (req, res, next) => {
  try {
    const quizMain = await Quiz.findById(req.params.id);

    req.quiz = quizMain;

    // res.status(200).json({
    //   status: "success",
    //   data: {
    //     quizMain,
    //   },
    // });
    next();
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};

exports.mega = (req, res, next) => {
  try {
    console.log("hellloooo");

    res.status(200).json({
      status: "success",
    });
    next();
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};

exports.submitquiz = async (req, res, next) => {
  try {
    const userID = req.user.id;
    const submit_array = req.body.submitQuiz_array;
    const quizID = req.body.id;
    const temp_array = await Quiz.findById(quizID);
    let correct_array = [];

    let attempted = 0;
    let correct = 0;
    let total = submit_array.length;
    let incorrect = 0;

    for (let i = 0; i < submit_array.length; i++) {
      let newArray = temp_array.questions[i].correct;
      if (!submit_array[i] == "") {
        attempted++;
      }
      correct_array.push(newArray);
    }

    for (let i = 0; i < total; i++) {
      if (correct_array[i] == submit_array[i]) {
        correct++;
      }
    }

    incorrect = attempted - correct;

    dataScore = {
      total,
      attempted,
      correct,
      incorrect,
    };

    let score = correct * 100 - incorrect * 20;

    let user_temp = await User.findById(userID);
    let credits = user_temp.credits + score;

    let quizzesTaken = user_temp.quizzesTaken;
    let temp_array_quiz = {
      quizID,
      score,
      attempted,
      correct,
    };
    console.log(quizzesTaken);
    quizzesTaken.push(temp_array_quiz);
    let takenBy = temp_array.takenBy;
    console.log(takenBy, "takenby");

    let temp_user = {
      userID,
      score,
      attempted,
      correct,
    };
    takenBy.push(temp_user);

    const user = await User.findByIdAndUpdate(
      userID,
      {
        quizzesTaken: quizzesTaken,
        credits: credits,
      },
      {
        new: true,
        runValidators: true,
      }
    );

    const quiz = await Quiz.findByIdAndUpdate(
      quizID,
      { takenBy: takenBy },
      {
        new: true,
        runValidators: true,
      }
    );

    res.status(200).json({
      status: "success",
      user,
      quiz,
      userID,
      quizID,
    });
  } catch (err) {
    res.status(200).json({
      status: "fail",
      message: err,
    });
  }
};
