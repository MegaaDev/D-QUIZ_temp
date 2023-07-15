import axios from "axios";
import { showAlert } from "./alerts";
export const bioFunction = async (formData) => {
  try {
    console.log("hellofrombio");

    const res = await axios({
      method: "PATCH",
      url: "http://localhost:8001/api/users/bio",
      data: formData,
    });
    if (res.data.status === "success") {
      console.log("megaapls");

      showAlert("success", "Added bio successfully");
      window.setTimeout(() => {
        location.assign("/");
      }, 1500);
    }
  } catch (err) {
    // console.log(error);
    console.log(err);

    showAlert("error", err);
  }
};
