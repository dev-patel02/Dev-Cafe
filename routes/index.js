import express from "express";
import tenantRoutes from "./tenant.js";
import authorize from "../middleware/authentication.js";
const router = express.Router();

// User
router.use("/tenant", tenantRoutes);

// Admin
// router.use("/tenants", authorize, user.getProducts);

export default router;
