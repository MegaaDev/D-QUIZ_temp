import axios from "axios";
import { showAlert } from "./alerts";

export const createQUIZ = async (
  title,
  description,
  questions,
  difficulty,
  tags,
  status
) => {
  try {
    console.log("heloooooooo");
    const res = await axios({
      method: "POST",
      url: "http://localhost:8001/api/quiz/createquiz",
      data: {
        title,
        description,
        questions,
        difficulty,
        tags,
        status,
      },
    });
    if (res.data.status === "success") {
      console.log("megaa");

      showAlert("success", "Quiz Created!");
      window.setTimeout(() => {
        location.assign("/");
      }, 500);
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
