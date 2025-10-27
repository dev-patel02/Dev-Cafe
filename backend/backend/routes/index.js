import express from "express";
import tenantRoutes from "./tenant.js";
import authorize from "../middleware/authentication.js";
const router = express.Router();

// tenant
router.use("/tenant", tenantRoutes);

// Master
router.use("/master", );

export default router;
