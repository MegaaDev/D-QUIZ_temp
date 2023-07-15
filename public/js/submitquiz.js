import axios from "axios";
import { showAlert } from "./alerts";

export const submitQuiz = async (submitQuiz_array, id) => {
  try {
    console.log("heloooooooo");
    const res = await axios({
      method: "POST",
      url: "http://localhost:8001/api/quiz/submitquiz",
      data: {
        submitQuiz_array,
        id,
      },
    });
    if (res.data.status === "success") {
      window.setTimeout(() => {
        const quizID = res.data.quizID;
        const userID = res.data.userID;
        console.log("megaaaaaaaaaaaaaaaaa");

        location.assign(`/scorepage/${userID}/${quizID}`);
      }, 10);
    }
  } catch (err) {
    if (err.response.data.message.errors) {
      console.log(
        err.response.data.message.errors[
          Object.keys(err.response.data.message.errors)[0]
        ].message
      );

      showAlert(
        "error",
        err.response.data.message.errors[
          Object.keys(err.response.data.message.errors)[0]
        ].message
      );
    } else {
      showAlert("error", "Oops something went wrong");
    }
  }
};
