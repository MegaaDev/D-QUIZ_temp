const express = require("express");
const userRoute = require("./routes/userRoute");
const quizRoute = require("./routes/quizRoute");
const viewRoute = require("./routes/viewRoute");

const morgan = require("morgan");
const path = require("path");

const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongoSanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const hpp = require("hpp");
const cors = require("cors");

const app = express();

app.set("view engine", "pug");
app.set("views", path.join(__dirname, "views"));
app.use(express.static(path.join(__dirname, "public")));

app.use(helmet({ contentSecurityPolicy: false }));
// if (process.env.NODE_ENV === "development") {
//   app.use(morgan("dev"));
// }

const limiter = rateLimit({
  max: 100,
  windowMs: 60 * 60 * 1000,
  message: "too many request from this IP, please try again after an hour",
});

app.use("/api", limiter);

app.use(express.json());
app.use(cookieParser());
app.use(mongoSanitize());

app.use(xss());
app.use(cors());

// app.use(
//   hpp({
//     whitelist: [
//       'duration',
//       'ratingsQuantity',
//       'ratingsAverage',
//       'maxGroupSize',
//       'difficulty',
//       'price',
//     ],
//   })
// );

app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next();
});
app.use(express.json());

app.use("/", viewRoute);

app.use("/api/users", userRoute);
app.use("/api/quiz", quizRoute);

module.exports = app;
