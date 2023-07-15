import "@babel/polyfill";
import { signup } from "./signup";
import { bioFunction } from "./bio";
import { createQUIZ } from "./quiz";
import { login } from "./login";
import { logout } from "./logout";
import { takeQuizPage } from "./takequiz";
import { submitQuiz } from "./submitquiz";
import { searchUser } from "./searchuser";
import { doc } from "prettier";
import { sendRequest } from "./sendreq";
const Friend = require("./../../models/friendModel");

if (document.querySelector(".signUp-button")) {
  document.querySelector(".signUp-button").addEventListener("click", (e) => {
    console.log("heloooooooo");

    const name = document.getElementById("name").value;
    const username = document.getElementById("username").value;
    const passwordConfirm = document.getElementById("passwordConfirm").value;

    const email = document.getElementById("email").value;
    const password = document.getElementById("password").value;
    signup(name, username, email, password, passwordConfirm);
  });
}

if (document.querySelector(".create-quiz-button")) {
  document
    .querySelector(".create-quiz-button")
    .addEventListener("click", (e) => {
      console.log("heloooooooo");
      const questions_array = [];

      for (let i = 0; i < question_count; i++) {
        let number = i + 1;
        let question = document.getElementById(`question${i + 1}`).value;
        let choice1 = document.getElementById(`choice1For${i + 1}`).value;
        let choice2 = document.getElementById(`choice2For${i + 1}`).value;

        let choice3 = document.getElementById(`choice3For${i + 1}`).value;

        let choice4 = document.getElementById(`choice4For${i + 1}`).value;
        let correct;
        for (let j = 1; j <= 4; j++) {
          if (
            document
              .querySelector(`.template${i + 1} .mini-template-${j}`)
              .classList.contains("correct-answer")
          ) {
            correct = document.querySelector(
              `.template${i + 1} .mini-template-${j}`
            ).innerHTML;
          }
        }
        let temp_array = {
          number: number,
          question: question,
          choice1: choice1,
          choice2: choice2,
          choice3: choice3,
          choice4: choice4,
          correct: correct,
        };

        questions_array[i] = temp_array;
      }

      const title = document.getElementById("quiz_title").value;
      const description = document.getElementById("quiz_description").value;
      const tags = document.getElementById("quiz_tags").value;
      const questions = questions_array;
      const difficulty = quiz_difficulty;
      const status = quiz_status;

      createQUIZ(title, description, questions, difficulty, tags, status);
    });
}

if (document.querySelector(".login-button")) {
  document.querySelector(".login-button").addEventListener("click", (e) => {
    const email = document.getElementById("loginemail").value;
    const password = document.getElementById("loginpassword").value;
    login(email, password);
  });
}

if (document.querySelector(".settings")) {
  document.querySelector(".settings").addEventListener("click", (e) => {
    console.log("hello");

    window.location.href = "/settings";
  });
}

if (document.querySelector(".sign-up-home")) {
  document.querySelector(".sign-up-home").addEventListener("click", (e) => {
    console.log("hello");

    window.location.href = "/signup";
  });
}

if (document.querySelector(".logout")) {
  document.querySelector(".logout").addEventListener("click", (e) => {
    logout();
  });
}

if (document.querySelector(".create-quiz")) {
  document.querySelector(".create-quiz").addEventListener("click", (e) => {
    window.location.href = "/createquiz";
  });
}

if (document.querySelector(".back-to-home")) {
  document.querySelector(".back-to-home").addEventListener("click", (e) => {
    window.location.href = "/";
  });
}

if (document.querySelector(".my-profile")) {
  document.querySelector(".my-profile").addEventListener("click", (e) => {
    window.location.href = "/myprofile";
  });
}

if (document.querySelector(".user-photo img")) {
  document.querySelector(".user-photo img").addEventListener("click", (e) => {
    window.location.href = "/myprofile";
  });
}

if (document.querySelector(".exit-quiz-click-button")) {
  document
    .querySelector(".exit-quiz-click-button")
    .addEventListener("click", (e) => {
      window.location.href = "/";
    });
}
if (document.querySelector(".button-discover")) {
  document.querySelector(".button-discover").addEventListener("click", (e) => {
    window.location.href = "/people";
  });
}

if (document.querySelector(".friends")) {
  document.querySelector(".friends").addEventListener("click", (e) => {
    window.location.href = "/friends";
  });
}

if (document.querySelector(".back-to-friends")) {
  document.querySelector(".back-to-friends").addEventListener("click", (e) => {
    window.location.href = "/friends";
  });
}

if (document.querySelector(".friend-accepted-profile")) {
  document
    .querySelector(".friend-accepted-profile")
    .addEventListener("click", (e) => {
      const userIDnew = document.querySelector(
        ".friend-accepted-profile-id"
      ).textContent;
      let userID = userIDnew.replace(/ /g, "");
      window.location.href = `/showprofile/${userID}`;
    });
}

if (document.querySelector(".people")) {
  document.querySelector(".people").addEventListener("click", (e) => {
    window.location.href = "/people";
  });
}

if (document.querySelector(".home")) {
  document.querySelector(".home").addEventListener("click", (e) => {
    window.location.href = "/";
  });
}

if (document.querySelector(".Login-here p")) {
  document.querySelector(".Login-here p").addEventListener("click", (e) => {
    window.location.href = "/login";
  });
}

if (document.querySelector(".bio-submit-button")) {
  document
    .querySelector(".bio-submit-button")
    .addEventListener("click", (e) => {
      e.preventDefault();
      const bio = document.getElementById("bio").value;

      let tagArray = [];
      for (let i = 0; i < 9; i++) {
        tagArray.push(
          document.querySelectorAll(".tag-set")[i].innerHTML.toString()
        );
      }
      console.log("hello");
      const tags = tagArray;
      const formData = new FormData();
      formData.append("photo", document.getElementById("photo").files[0]);
      formData.append("tags", tags);
      formData.append("bio", bio);
      console.log(formData);

      bioFunction(formData);
    });
}

let quiz_difficulty = "easy";

if (
  document.querySelector(".easy-input") ||
  document.querySelector(".medium-input") ||
  document.querySelector(".difficult-input")
) {
  document.querySelector(".easy-input").addEventListener("click", () => {
    document.querySelector(".easy-input").style.backgroundColor = " #47b912";
    document.querySelector(".medium-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    document.querySelector(".difficult-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    quiz_difficulty = "easy";
  });

  document.querySelector(".medium-input").addEventListener("click", () => {
    document.querySelector(".easy-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    document.querySelector(".medium-input").style.backgroundColor = "#dcb014";
    document.querySelector(".difficult-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    quiz_difficulty = "medium";
  });
  document.querySelector(".difficult-input").addEventListener("click", () => {
    document.querySelector(".easy-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    document.querySelector(".medium-input").style.backgroundColor =
      "rgb(15, 15, 16)";
    document.querySelector(".difficult-input").style.backgroundColor =
      "#a84242";
    quiz_difficulty = "difficult";
  });
}

let quiz_status = "public";
if (document.querySelector(".quiz-status")) {
  document.querySelector(".public-quiz").addEventListener("click", () => {
    document.querySelector(".public-quiz").style.backgroundColor = " #0dc9be";
    document.querySelector(".private-quiz").style.backgroundColor =
      "rgb(197, 197, 197)";

    quiz_status = "public";
  });

  document.querySelector(".private-quiz").addEventListener("click", () => {
    document.querySelector(".public-quiz").style.backgroundColor =
      "rgb(197, 197, 197)";
    document.querySelector(".private-quiz").style.backgroundColor = "#0dc9be";

    quiz_status = "private";
  });
}

///
let trustBool = true;
const trialFunction = () => {
  for (let i = 1; i <= question_count; i++) {
    document.querySelector(`.cross-exit${i}`).addEventListener("click", () => {
      if (trustBool) {
        if (document.querySelector(`.template${i}`)) {
          document.querySelector(`.template${i}`).remove();
        }

        for (let j = i + 1; j <= question_count; j++) {
          console.log("working");

          document
            .querySelector(`.template${j}`)
            .classList.add(`template${j - 1}`);
          document
            .querySelector(`.template${j}`)
            .classList.remove(`template${j}`);

          document
            .querySelector(`.question-count${j}`)
            .classList.add(`question-count${j - 1}`);
          document.querySelector(`.question-count${j}`).innerHTML = `${j - 1}`;
          document
            .querySelector(`.question-count${j}`)
            .classList.remove(`question-count${j}`);

          document
            .querySelector(`.cross-exit${j}`)
            .classList.add(`cross-exit${j - 1}`);

          document
            .querySelector(`.cross-exit${j}`)
            .classList.remove(`cross-exit${j}`);
        }

        trustBool = false;

        question_count -= 1;
        console.log(question_count + 10);
      }
    });
    trustBool = true;
  }
};
let abcda;
let question_count = 0;
let quiz_question_array = {};
let exclude_count = [];
if (document.querySelector(".add-question")) {
  document.querySelector(".add-question").addEventListener("click", () => {
    console.log(question_count + 10);

    question_count++;

    let abcda = document.createElement(`div`);
    let htmlElements = `<div class="question-ans-block">
    <div class="question-count question-count${question_count}">${question_count}</div>
  
    <div class="question-span">
      <div class="straight-span">
      <div class="enter-question">
        <input id = "question${question_count}" type="text" placeholder="Enter Questionss" />
      </div>
      <div class="crossit">
      <img class="cross-exit cross-exit${question_count}" src="./../images/cross.png" alt="" />
        
      </div>
      </div>
      <div class="choices-1">
        <div class="choice-A ">
          <div  class="choice-name mini-template-1">A</div>
          <div class="choice-input"><input  id="choice1For${question_count}" type="text" /></div>
        </div>
        <div class="choice-B ">
          <div class="choice-name mini-template-2">B</div>
          <div class="choice-input"><input id="choice2For${question_count}" type="text" /></div>
        </div>
      </div>
      <div class="choices-2">
        <div class="choice-C  ">
          <div class="choice-name mini-template-3">C</div>
          <div class="choice-input"><input id="choice3For${question_count}" type="text" /></div>
        </div>
        <div class="choice-D ">
          <div class="choice-name mini-template-4">D</div>
          <div class="choice-input"><input id="choice4For${question_count}" type="text" /></div>
        </div>
      </div>
    </div>
    </div> `;

    abcda.innerHTML = htmlElements;
    abcda.className = `template${question_count}`;
    document.querySelector(".add-question-template").append(abcda);

    let question_temp = question_count;
    for (let i = 1; i <= 4; i++) {
      document
        .querySelector(`.template${question_temp} .mini-template-${i}`)
        .addEventListener("click", () => {
          document
            .querySelector(`.template${question_temp} .mini-template-${i}`)
            .classList.add("correct-answer");

          for (let j = 1; j <= 4; j++) {
            if (
              i !== j &&
              document
                .querySelector(`.template${question_temp} .mini-template-${j}`)
                .classList.contains("correct-answer")
            ) {
              document
                .querySelector(`.template${question_temp} .mini-template-${j}`)
                .classList.remove("correct-answer");
            }
          }
        });
    }

    trialFunction();
  });
}

if (document.querySelector(".tag-set ")) {
  for (let i = 1; i <= 9; i++) {
    document.querySelector(`.tag-${i}`).addEventListener("click", () => {
      if (
        !document.querySelector(`.tag-${i}`).classList.contains("select-tag")
      ) {
        document.querySelector(`.tag-${i}`).classList.add("select-tag");
        if (
          document.querySelector(`.tag-${i}`).classList.contains("deselect-tag")
        ) {
          document.querySelector(`.tag-${i}`).classList.remove("deselect-tag");
        }
      } else {
        document.querySelector(`.tag-${i}`).classList.remove("select-tag");
        document.querySelector(`.tag-${i}`).classList.add("deselect-tag");
      }
    });
  }
}

let varClass = document.querySelectorAll(".your-quiz.mega-home-page").length;

// for (let i = 0; i < varClass; i++) {
//   document
//     .querySelectorAll(".your-quiz.mega-home-page")
//     [i].addEventListener("click", () => {
//       let title = document.querySelectorAll(
//         ".your-quiz.mega-home-page .quiz-title"
//       )[i].textContent;

//       let description = document.querySelectorAll(
//         ".your-quiz.mega-home-page .your-quiz-middle"
//       )[i].textContent;

//       let difficulty = document.querySelectorAll(
//         ".your-quiz.mega-home-page .difficulty"
//       )[i].textContent;
//       console.log(title, description, difficulty);

//       takeQuizPage(title, description, difficulty);
//     });
// }

for (let i = 0; i < varClass; i++) {
  document
    .querySelectorAll(".your-quiz.mega-home-page")
    [i].addEventListener("click", () => {
      let idnew = document.querySelectorAll(
        ".your-quiz.mega-home-page .quiz-id"
      )[i].textContent;
      // console.log(id);
      let id = idnew.replace(/ /g, "");

      window.location.href = `/takequiz/${id}`;
    });
}
if (document.querySelector(".take-quiz-click-button")) {
  document
    .querySelector(".take-quiz-click-button")
    .addEventListener("click", () => {
      let varID = document.querySelector(".title-box .temp-id").textContent;
      let id = varID.replace(/ /g, "");
      console.log(id);

      // let qidnew = document.querySelector(
      //   ".title-box .temp-question-id"
      // ).textContent;

      window.location.href = `/attemptquiz/${id}`;
    });
}

let megaBool = true;
if (document.querySelector(".take-quiz-title-length")) {
  if (megaBool) {
    window.addEventListener("load", (event) => {
      for (let i = 1; i < questions_number; i++) {
        document
          .querySelectorAll(".question-section")
          [i].classList.add("hideIT");
      }
    });
  }
  let questions_number = Number(
    document.querySelector(".take-quiz-title-length").textContent
  );
  console.log(questions_number);
  for (let i = 0; i < questions_number; i++) {
    document
      .querySelectorAll(".quiz-snippet")
      [i].addEventListener("click", () => {
        megaBool = false;
        let number = document.querySelectorAll(".quiz-snippet")[i].textContent;
        console.log(number);

        for (let j = 0; j < questions_number; j++) {
          if (i !== j) {
            document
              .querySelectorAll(".question-section")
              [j].classList.add("hideIT");

            if (
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.contains("attempting")
            ) {
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.remove("attempting");
            }
          } else {
            document
              .querySelectorAll(".question-section")
              [j].classList.remove("hideIT");
            if (
              !document
                .querySelectorAll(".quiz-snippet")
                [j].classList.contains("attempting")
            ) {
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.add("attempting");
            }
          }
        }
      });
  }
}

if (document.querySelector(".clear-button")) {
}

if (document.querySelector(`.options-take-quiz`)) {
  let questions_number = Number(
    document.querySelector(".take-quiz-title-length").textContent
  );
  for (let k = 0; k < questions_number; k++) {
    for (let i = 1; i <= 4; i++) {
      document
        .querySelectorAll(`.options-take-quiz.option-${i}`)
        [k].addEventListener("click", () => {
          console.log("clickedd");

          document
            .querySelectorAll(`.options-take-quiz.option-${i}`)
            [k].classList.add("correct-answer-take");

          if (
            document
              .querySelectorAll(`.options-take-quiz.option-${i}`)
              [k].classList.contains("correct-answer-take")
          ) {
            document
              .querySelectorAll(".quiz-snippet")
              [k].classList.remove("attempting");
            document
              .querySelectorAll(".quiz-snippet")
              [k].classList.add("attempted");
          }

          for (let j = 1; j <= 4; j++) {
            if (
              i !== j &&
              document
                .querySelectorAll(`.options-take-quiz.option-${j}`)
                [k].classList.contains("correct-answer-take")
            ) {
              document
                .querySelectorAll(`.options-take-quiz.option-${j}`)
                [k].classList.remove("correct-answer-take");
            }
          }
        });
    }
  }
}

if (document.querySelector(".take-quiz-title-length")) {
  let questions_number = Number(
    document.querySelector(".take-quiz-title-length").textContent
  );
  for (let k = 0; k < questions_number; k++) {
    document
      .querySelectorAll(".clear-button")
      [k].addEventListener("click", () => {
        for (let i = 1; i <= 4; i++) {
          if (
            document
              .querySelectorAll(`.options-take-quiz.option-${i}`)
              [k].classList.contains("correct-answer-take")
          ) {
            document
              .querySelectorAll(`.options-take-quiz.option-${i}`)
              [k].classList.remove("correct-answer-take");
          }
        }
        if (
          document
            .querySelectorAll(".quiz-snippet")
            [k].classList.contains("attempted")
        ) {
          document
            .querySelectorAll(".quiz-snippet")
            [k].classList.remove("attempted");
        }
      });
  }
}

if (document.querySelector(".next-button")) {
  console.log("helo");

  let questions_number = Number(
    document.querySelector(".take-quiz-title-length").textContent
  );
  console.log(questions_number);

  for (let k = 0; k < questions_number - 1; k++) {
    console.log("happend");

    document
      .querySelectorAll(".next-button")
      [k].addEventListener("click", () => {
        console.log(k, "ej");

        for (let j = 0; j < questions_number; j++) {
          if (k !== j - 1) {
            document
              .querySelectorAll(".question-section")
              [j].classList.add("hideIT");

            if (
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.contains("attempting")
            ) {
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.remove("attempting");
            }
          } else {
            document
              .querySelectorAll(".question-section")
              [j].classList.remove("hideIT");
            if (
              !document
                .querySelectorAll(".quiz-snippet")
                [j].classList.contains("attempting")
            ) {
              document
                .querySelectorAll(".quiz-snippet")
                [j].classList.add("attempting");
            }
          }
        }
      });
  }
}

// if (document.querySelector(".submit-quiz")) {
//   let questions_number = Number(
//     document.querySelector(".take-quiz-title-length").textContent
//   );
//   let total = questions_number;
//   let attempted = 0;
//   let correct = 0;
//   let incorrect = 0;
//   document.querySelector(".submit-quiz").addEventListener("click", () => {
//     let submitQuiz_array = [];
//     for (let i = 0; i < questions_number; i++) {
//       for (let j = 1; j <= 4; j++) {
//         if (
//           document
//             .querySelectorAll(`.options-take-quiz.option-${j}`)
//             [i].classList.contains("correct-answer-take")
//         ) {
//           attempted++;
//           let clickedAnswer = document.querySelectorAll(
//             `.options-take-quiz.option-${j} .options-quiz-take`
//           )[i].textContent;
//           let actualAnswer;

//           for (let k = 1; k <= 4; k++) {
//             if (
//               document
//                 .querySelectorAll(
//                   `.options-take-quiz.option-${j} .options-quiz-take`
//                 )
//                 [k].classList.contains("correct-option")
//             ) {
//               actualAnswer = document.querySelectorAll(
//                 `.options-take-quiz.option-${j} .options-quiz-take`
//               )[k].textContent;
//             }
//           }

//           if (clickedAnswer == actualAnswer) {
//             correct++;
//           } else {
//             incorrect++;
//           }

//           break;
//         }
//       }
//     }

//     console.log(total, attempted, correct, incorrect);
//   });
// }

if (document.querySelector(".submit-quiz")) {
  let questions_number = Number(
    document.querySelector(".take-quiz-title-length").textContent
  );
  console.log("heyaaaa");

  document.querySelector(".submit-quiz").addEventListener("click", () => {
    let submitQuiz_array = [];
    for (let i = 0; i < questions_number; i++) {
      let varBool = true;
      for (let j = 1; j <= 4; j++) {
        if (
          document
            .querySelectorAll(`.options-take-quiz.option-${j}`)
            [i].classList.contains("correct-answer-take")
        ) {
          let clickedAnswer = document.querySelectorAll(
            `.options-take-quiz.option-${j} .options-quiz-take`
          )[i].textContent;
          submitQuiz_array.push(clickedAnswer);
          varBool = false;
          break;
        }
      }
      if (varBool) {
        submitQuiz_array.push("");
      }
    }
    let varID = document.querySelector(".take-quiz-id").textContent;
    let id = varID.replace(/ /g, "");
    submitQuiz(submitQuiz_array, id);
  });
}

if (document.querySelector(".click-to-search")) {
  document.querySelector(".click-to-search").addEventListener("click", () => {
    const searchedUser = document.getElementById("search-users").value;
    window.location.href = `/people?username=${searchedUser}`;
  });

  document.addEventListener("keydown", (e) => {
    if (e.key == "Enter") {
      const searchedUser = document.getElementById("search-users").value;
      window.location.href = `/people?username=${searchedUser}`;
    }
  });
}

if (document.querySelector(".friend-card")) {
  let users_count = document.querySelector(".users-count").textContent;
  for (let i = 0; i < users_count; i++) {
    document
      .querySelectorAll(".friend-name")
      [i].addEventListener("click", () => {
        let userIDnew = document.querySelectorAll(".friend-card .people-id")[i]
          .textContent;
        let userID = userIDnew.replace(/ /g, "");
        window.location.href = `/showprofile/${userID}`;
      });
  }
}

if (document.querySelector(".temp-class")) {
  let quiz_count = document.querySelector(".quiz-length-profile").textContent;
  for (let i = 0; i < quiz_count; i++) {
    document.querySelectorAll(".your-quiz")[i].addEventListener("click", () => {
      let idnew = document.querySelectorAll(".your-quiz .quiz-id-profile ")[i]
        .textContent;
      let id = idnew.replace(/ /g, "");

      window.location.href = `/takequiz/${id}`;
    });
  }
}

if (document.querySelector(".quiz-total-length")) {
  let quiz_count = document.querySelector(".quiz-total-length").textContent;
  for (let i = 0; i < quiz_count; i++) {
    document
      .querySelectorAll(".score-snippets")
      [i].addEventListener("click", () => {
        add - friend - logo;
        const temp1ID = document.querySelectorAll(
          ".score-snippets .quiz-score-user"
        )[i].textContent;
        const temp2ID = document.querySelectorAll(
          ".score-snippets .quiz-score-quiz-id"
        )[i].textContent;

        const userID = temp1ID.replace(/ /g, "");
        const quizID = temp2ID.replace(/ /g, "");
        window.location.href = `/scorepage/${userID}/${quizID}`;
      });
  }
}

if (document.querySelector(".add-friend-logo")) {
  let peopleCount = document.querySelector(".users-count").textContent;

  for (let i = 0; i < peopleCount; i++) {
    document
      .querySelectorAll(".add-friend-logo")
      [i].addEventListener("click", (e) => {
        e.preventDefault();
        console.log("helo");

        document
          .querySelectorAll(".add-friend-logo")
          [i].classList.add("hideIT");
        document
          .querySelectorAll(".request-logo")
          [i].classList.remove("hideIT");
        setTimeout(() => {
          const recidNew = document.querySelectorAll(".friend-name .people-id")[
            i
          ].textContent;

          const recid = recidNew.replace(/ /g, "");
          sendRequest(recid);
        }, 500);
      });
  }
}

if (document.querySelector(".incoming-requests")) {
  document.querySelector(".incoming-requests").addEventListener("click", () => {
    window.location.href = "/incomingrequest";
  });
}

if (document.querySelector(".accept-request")) {
  let request_length = document.querySelector(
    ".incoming-requests-length"
  ).textContent;
  for (let i = 0; i < request_length; i++) {
    document
      .querySelectorAll(".accept-request")
      [i].addEventListener("click", () => {
        const recidnew = document.querySelector(
          ".reciever-id-secret"
        ).textContent;
        document.querySelectorAll(".accept-request")[i].classList.add("hideIT");
        document.querySelectorAll(".reject-request")[i].classList.add("hideIT");
        document
          .querySelectorAll(".request-accepted")
          [i].classList.remove("hideITT");

        const recid = recidnew.replace(/ /g, "");
        window.location.href = `/acceptedrequest/${recid}`;
      });
  }
}

if (document.querySelector(".reject-request")) {
  let request_length = document.querySelector(
    ".incoming-requests-length"
  ).textContent;
  for (let i = 0; i < request_length; i++) {
    document
      .querySelectorAll(".reject-request")
      [i].addEventListener("click", () => {
        const recidnew = document.querySelector(
          ".reciever-id-secret"
        ).textContent;
        document.querySelectorAll(".reject-request")[i].classList.add("hideIT");
        document.querySelectorAll(".accept-request")[i].classList.add("hideIT");
        document
          .querySelectorAll(".request-rejected")
          [i].classList.remove("hideITT");

        const recid = recidnew.replace(/ /g, "");
        window.location.href = `/rejectedrequest/${recid}`;
      });
  }
}

if (document.querySelector(".name-incoming-request")) {
  let request_length = document.querySelector(
    ".incoming-requests-length"
  ).textContent;
  for (let i = 0; i < request_length; i++) {
    document
      .querySelectorAll(".name-incoming-request p")
      [i].addEventListener("click", () => {
        const userIDnew = document.querySelector(
          ".reciever-id-secret"
        ).textContent;

        const userID = userIDnew.replace(/ /g, "");
        window.location.href = `/showprofile/${userID}`;
      });

    document
      .querySelectorAll(".name-incoming-request img")
      [i].addEventListener("click", () => {
        const userIDnew = document.querySelector(
          ".reciever-id-secret"
        ).textContent;

        const userID = userIDnew.replace(/ /g, "");
        window.location.href = `/showprofile/${userID}`;
      });
  }
}

if (document.querySelector(".friend-card-actual")) {
  let friends_length = document.querySelector(
    ".your-friends-length"
  ).textContent;

  for (let i = 0; i < friends_length; i++) {
    document
      .querySelectorAll(".friend-card-actual")
      [i].addEventListener("click", () => {
        const userIDnew =
          document.querySelector(".friend-id-view ").textContent;
        const userID = userIDnew.replace(/ /g, "");
        window.location.href = `/showprofile/${userID}`;
      });
  }
}

if (document.querySelector(".outgoing-requests")) {
  document.querySelector(".outgoing-requests").addEventListener("click", () => {
    window.location.href = "/outgoingrequest";
  });
}
//

if (document.querySelector(".quiz-status")) {
  document.querySelector(".public-quiz").addEventListener("click", () => {
    document.querySelector(".public-quiz").style.backgroundColor = " #0dc9be";
    document.querySelector(".private-quiz").style.backgroundColor =
      "rgb(197, 197, 197)";

    quiz_status = "public";
  });

  document.querySelector(".private-quiz").addEventListener("click", () => {
    document.querySelector(".public-quiz").style.backgroundColor =
      "rgb(197, 197, 197)";
    document.querySelector(".private-quiz").style.backgroundColor = "#0dc9be";

    quiz_status = "private";
  });
}

if (document.querySelector(".length-secret-only")) {
  console.log("dsaflkasjdh");

  let private_number = document.querySelector(
    ".length-secret-only"
  ).textContent;

  for (let i = 0; i < private_number; i++) {
    document
      .querySelectorAll(".your-quiz-friend")
      [i].addEventListener("click", () => {
        let varID = document.querySelector(
          ".your-quiz-friend .quiz-id-profile-friend "
        ).textContent;
        let id = varID.replace(/ /g, "");
        console.log(id);

        window.location.href = `/takequiz/${id}`;
      });
  }
}
