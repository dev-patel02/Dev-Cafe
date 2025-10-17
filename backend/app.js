import express, { Router } from "express";
import dotenv from "dotenv";
import cors from "cors";
import router from "./routes/index.js";
import {
  Master,
  Orders,
  Products,
  Tenant,
  User,
} from "./models/association.js";
import { connectDB } from "./config/index.js";

dotenv.config({quiet:true});
const app = express();

app.use(cors());
app.use(express.json());
connectDB();

app.use("/", router);
app.listen(process.env.PORT, () => {});
