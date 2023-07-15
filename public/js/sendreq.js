import axios from "axios";
import { showAlert } from "./alerts";

export const sendRequest = async (recid) => {
  try {
    console.log("heloooooooo");
    const res = await axios({
      method: "POST",
      url: `http://localhost:8001/api/users/friendrequest/${recid}`,
      data: { recid },
    });
    if (res.data.status === "success") {
      console.log("megaa");

      showAlert("success", "Request Sent");
      window.setTimeout(() => {
        location.assign(`/friendrequest/${recid}`);
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
    }
    // else if (err.response.data.message) {
    //   console.log(err.response.data.message);

    //   showAlert(err.response.data.message);
    // }
    else {
      console.log("codeeee");

      showAlert("Something went wrong!!!");
    }
  }
};
