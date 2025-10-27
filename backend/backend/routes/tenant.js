import express from "express";
import tenant from "../controllers/tenant.js"

const router = express.Router();

router.post("/login", tenant.login)

export default router