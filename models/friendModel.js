const mongoose = require("mongoose");

const friendRequest = new mongoose.Schema({
  requester: {
    type: String,
  },
  reciever: {
    type: String,
  },
  status: {
    type: Number,
  },
});

const Friend = mongoose.model("Friend", friendRequest);

module.exports = Friend;
