import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config({quiet:true});

let authorize = (req, res, next) => {
  let token = req.headers["authorization"].split(" ")[1];
  if (!token) {
    res.status(500).json({
      log: "You Didn't Provide Token!!!",
    });
  }
  jwt.verify(token, process.env.JWT_TOKEN, (err, result) => {
    if (err) {
      res.status(500).json({
        log: "Token Is Invalid",
        Error: err.message,
      });
    }
    req.jwtData = result;
    // res.json(req.jwtData )
    // console.log(req.jwtData)
  });
  next();
};
export default authorize;
