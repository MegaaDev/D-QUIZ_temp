import axios from "axios";
import { showAlert } from "./alerts";
export const takeQuizPage = async (id) => {
  try {
    // console.log(title, "eessdd");

    const res = await axios({
      method: "get",
      url: `http://localhost:8001/api/quiz/takequiz/${id}`,
      data: {
        id,
      },
    });
    // console.log(title, "edddddddes");

    if (res.data.status === "success") {
      // console.log("megaapls");
      // console.log(title, "eejjijijijs");

      showAlert("success", "Added bio successfully");
      window.setTimeout(() => {
        location.assign("/takequiz");
      }, 500);
    }
  } catch (err) {
    // console.log(error);
    console.log(err);

    showAlert("error", err);
  }
};
