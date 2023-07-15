const Friend = require("../models/friendModel");
const Quiz = require("./../models/quizModel");
const User = require("./../models/userModel");
exports.signup = (req, res) => {
  res.status(200).render("signup", {
    title: "Sign up",
  });
};

exports.login = (req, res) => {
  res.status(200).render("login", {
    title: "login",
  });
};

exports.bio = (req, res) => {
  res.status(200).render("bio", {
    title: "your bio",
  });
};

exports.home = async (req, res) => {
  const quizzes = await Quiz.find({ status: { $ne: "private" } });
  // console.log(req.user, "jhkgkgug");

  res.status(200).render("home", {
    title: "home",
    quizzes,
  });
};
exports.createquiz = (req, res) => {
  res.status(200).render("quizCreate", {
    title: "home",
  });
};

exports.settings = async (req, res) => {
  res.status(200).render("settings", {
    title: "logout",
  });
};

exports.myprofile = async (req, res) => {
  const user = await User.findById(req.user.id);
  const quizzes = await Quiz.find({ userID: req.user.id });
  console.log(user.quizzesTaken);

  let quiz_array = [];
  for (let i = 0; i < user.quizzesTaken.length; i++) {
    const quiz = await Quiz.findById(user.quizzesTaken[i].quizID);
    const name = quiz.title;
    const score = user.quizzesTaken[i].score;
    const quizID = user.quizzesTaken[i].quizID;

    let temp_array = {
      name,
      score,
      quizID,
    };
    quiz_array.push(temp_array);
  }

  res.status(200).render("myprofile", {
    title: "myProfile",
    user,
    quizzes,
    quiz_array,
  });
};

exports.takequiz = async (req, res) => {
  // console.log(req.quiz, "megaaa");
  // const user = await User.findById(req.user.id);

  const quiznew = await Quiz.find(req.quiz);
  const quiz = quiznew[0];
  // req.locals.quiz = quiz[0];
  res.status(200).render("takequiz", {
    title: "Mega",
    quiz,
    // user,
  });
};

exports.attemptquiz = async (req, res) => {
  const quiz = await Quiz.findById(req.params.id);

  console.log(quiz.questions);

  res.status(200).render("attemptquiz", {
    title: "Mega",
    quiz,
    // quiz_question,
  });
};
exports.scorepage = async (req, res) => {
  console.log(req.params);

  const userID = req.params.uid;
  const quizID = req.params.qid;

  const user = await User.find({ _id: userID });
  const quiz = await Quiz.findById(quizID);

  let score_array = {};

  for (let i = 0; i < user[0].quizzesTaken.length; i++) {
    if (user[0].quizzesTaken[i].quizID == quizID) {
      let score = user[0].quizzesTaken[i].score;
      let attempted = user[0].quizzesTaken[i].attempted;
      let total = quiz.questions.length;
      let correct = user[0].quizzesTaken[i].correct;
      let incorrect = attempted - correct;
      score_array = {
        score,
        attempted,
        total,
        correct,
        incorrect,
      };
      break;
    }
  }

  res.status(200).render("scorepage", {
    title: "Mega",
    quiz,
    score_array,
  });
};

exports.people = async (req, res) => {
  const userMe = await User.findById(req.user.id);

  let userQuery = User.find({ _id: { $ne: req.user.id } });
  let filter = {};
  if (req.query.username) {
    filter = req.query.username;
    userQuery = userQuery.find({
      username: { $regex: filter, $options: "i" },
    });
  }
  const users = await userQuery;

  res.status(200).render("people", {
    title: "Mega",
    users,
    userMe,
  });
};
exports.showprofile = async (req, res) => {
  const friend = await User.findById(req.user.id);
  const user = await User.findById(req.params.id);
  const quizzes = await Quiz.find({
    userID: req.params.id,
    status: { $ne: "private" },
  });

  const privateQuizzes = await Quiz.find({
    userID: req.params.id,
    status: { $ne: "public" },
  });

  let friendBool = false;
  for (let i = 0; i < friend.friends.length; i++) {
    if (friend.friends[i].friendID == user.id) {
      friendBool = true;
      break;
    }
  }

  total_length = quizzes.length + privateQuizzes.length;
  console.log(total_length);

  res.status(200).render("showprofile", {
    title: "showprofile",
    user,
    quizzes,
    friendBool,
    privateQuizzes,
    total_length,
  });
};

exports.sendReq = async (req, res) => {
  const requesterID = req.user.id;
  const recieverID = req.params.recid;
  const user = await User.findById(requesterID);

  const reciever = await User.findById(recieverID);
  console.log(user.photo);

  res.status(200).render("friendrequest", {
    title: "showprofile",
    reciever,
    user,
  });
};

exports.friends = async (req, res) => {
  const user = await User.findById(req.user.id);
  let friends_array = [];
  for (let i = 0; i < user.friends.length; i++) {
    let friend_temp = await User.findById(user.friends[i].friendID);
    let temp_array = {};
    let friendID = user.friends[i].friendID;
    let username = friend_temp.username;
    let photo = friend_temp.photo;
    let credits = friend_temp.credits;
    temp_array = {
      friendID,
      username,
      photo,
      credits,
    };
    friends_array.push(temp_array);
  }

  let friends = friends_array;
  res.status(200).render("friends", {
    title: "home",
    user,
    friends,
  });
};

exports.incomingrequest = async (req, res) => {
  const user = await User.findById(req.user.id);
  const friend = await Friend.find();

  let incomingrequest_array = [];

  for (let i = 0; i < friend.length; i++) {
    if (user.id == friend[i].reciever && friend[i].status == 1) {
      let friend_new = await User.findById(friend[i].requester);
      let name = friend_new.username;
      let credits = friend_new.credits;
      let photo = friend_new.photo;
      let recid = friend_new.id;
      console.log(user.username, name);

      let temp_array = {
        recid,
        name,
        credits,
        photo,
      };
      incomingrequest_array.push(temp_array);
    }
  }

  incomingrequests = incomingrequest_array;

  res.status(200).render("incomingrequest", {
    title: "Incoming Requests",
    incomingrequests,
  });
};

exports.acceptedrequest = async (req, res) => {
  const user = await User.findById(req.user.id);
  const requesterID = req.params.recid;
  console.log("heheeehehehehhehehe");
  const friend_user = await User.findById(requesterID);
  console.log(user.id, requesterID);

  const friend = await Friend.find({
    reciever: user.id,
    requester: requesterID,
  });
  console.log(friend[0]);
  const updateFriendship = await Friend.findByIdAndUpdate(friend[0].id, {
    status: 2,
  });

  let friends_user = {
    friendID: friend_user.id,
    friendName: friend_user.username,
  };

  let friends_friend_user = {
    friendID: user.id,
    friendName: user.username,
  };

  let friends_array_user = user.friends;
  friends_array_user.push(friends_user);

  let friends_array_friend_user = friend_user.friends;
  friends_array_friend_user.push(friends_friend_user);
  const userUpdate = await User.findByIdAndUpdate(
    req.user.id,
    {
      friends: friends_array_user,
    },
    {
      new: true,
      runValidators: true,
    }
  );

  const friendUpdate = await User.findByIdAndUpdate(
    requesterID,
    {
      friends: friends_array_friend_user,
    },
    {
      new: true,
      runValidators: true,
    }
  );
  res.status(200).render("acceptedrequest", {
    title: "home",
    user,
    friend: friend_user,
  });
};

exports.rejectedrequest = async (req, res) => {
  const user = await User.findById(req.user.id);
  const requesterID = req.params.recid;
  console.log("heheeehehehehhehehe");
  const friend_user = await User.findById(requesterID);
  console.log(user.id, requesterID);

  const friend = await Friend.find({
    reciever: user.id,
    requester: requesterID,
  });
  console.log(friend[0]);
  const updateFriendship = await Friend.findByIdAndUpdate(friend[0].id, {
    status: 3,
  });

  res.status(200).render("rejectedrequest", {
    title: "home",
    user,
    friend: friend_user,
  });
};
exports.outgoingrequest = async (req, res) => {
  const user = await User.findById(req.user.id);
  const friend = await Friend.find();

  let outgoing_array = [];

  for (let i = 0; i < friend.length; i++) {
    if (friend[i].requester == user.id && friend[i].status == 1) {
      let friend_new = await User.findById(friend[i].reciever);
      let name = friend_new.username;
      let credits = friend_new.credits;
      let photo = friend_new.photo;
      let recid = friend_new.id;

      let temp_array = {
        recid,
        name,
        credits,
        photo,
      };
      outgoing_array.push(temp_array);
    }
  }

  res.status(200).render("outgoingrequest", {
    title: "Outgoing Request",
    user,
    outgoing_array,
  });
};
