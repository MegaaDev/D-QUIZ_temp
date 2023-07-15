const mongoose = require("mongoose");
const questionSchema = new mongoose.Schema({
  number: {
    type: Number,
  },
  question: {
    type: String,
    required: [true, "Question required"],
    unique: true,
  },
  choice1: {
    type: String,
    required: [true, "Option required"],
  },
  choice2: {
    type: String,
    required: [true, "Option required"],
  },
  choice3: {
    type: String,
    required: [true, "Option required"],
  },
  choice4: {
    type: String,
    required: [true, "Option required"],
  },
  correct: {
    type: String,
    required: [true, "correct required"],
  },
});

const takenBySchema = new mongoose.Schema({
  userID: String,
  score: Number,
  attempted: Number,
  correct: Number,
});

const quizSchema = new mongoose.Schema({
  title: {
    type: String,
    required: [true, "Quiz title required"],
    minlength: [3, "min character length of quiz title is 3"],
    unique: true,
  },
  description: {
    type: String,
    required: [true, "Quiz description required"],
  },
  questions: {
    type: [questionSchema],
    validate: {
      validator: function (el) {
        return this.questions.length <= 12;
      },
    },
  },
  difficulty: {
    type: String,
    enum: ["easy", "medium", "difficult"],
  },
  tags: [String],

  userID: String,
  username: String,
  takenBy: {
    type: [takenBySchema],
  },
  status: {
    type: String,
    default: "public",
    enum: ["public", "private"],
  },
});

const Quiz = mongoose.model("Quiz", quizSchema);
module.exports = Quiz;
