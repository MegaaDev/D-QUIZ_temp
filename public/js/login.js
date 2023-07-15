import axios from "axios";
import { showAlert } from "./alerts";
export const login = async (email, password) => {
  try {
    console.log("heloooooooo");

    const res = await axios({
      method: "POST",
      url: "http://localhost:8001/api/users/login",
      data: {
        email,
        password,
      },
    });
    if (res.data.status === "success") {
      console.log("megaa");

      showAlert("success", "Logged in Successfully");
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

// export const logout = async () => {
//   try {
//     const res = await axios({
//       method: "GET",
//       url: "http://localhost:8000/api/v1/users/logout",
//     });
//     if (res.data.status == "success") {
//       showAlert("success", "Logged out Successfully");

//       location.reload(true);
//     }
//   } catch (err) {
//     showAlert("error", "Error logging out!");
//   }
// };
