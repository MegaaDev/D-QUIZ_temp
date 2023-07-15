import axios from "axios";
import { showAlert } from "./alerts";

export const logout = async () => {
  try {
    const res = await axios({
      method: "GET",
      url: "http://localhost:8001/api/users/logout",
    });

    if (res.data.status == "success") {
      showAlert("success", "Logged out Successfully");
      window.setTimeout(() => {
        window.location.href = "/signup";
      }),
        1500;
    }
  } catch (err) {
    showAlert("error", "Error logging out!");
  }
};
