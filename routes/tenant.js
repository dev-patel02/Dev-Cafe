import express from "express";
import tenant from "../controllers/tenant.js"
// import user from "../controller/user.js";
import authorize from "../middleware/authentication.js";

const router = express.Router();

router.post("/add", tenant.signUp)

export default router