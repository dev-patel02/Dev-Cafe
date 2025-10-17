import { sequelize } from "../config/index.js";
import { DataTypes } from "sequelize";

const Master = sequelize.define(
  "masters",
  {
    id: {
      type: DataTypes.INTEGER(3),
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.STRING(30),
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING(30),
      allowNull: false,
      unique: true,
      validate: {
        isEmail: true,
        isEmail: {
          msg: "Invalid Email Format",
        },
      },
      unique: {
        msg: "You're Email Already Exist!!!",
      },
    },
    password: {
      type: DataTypes.STRING,
      allowNull: false,
    },
  },
  {
    initialAutoIncrement: 1,
  }
);

export default Master;
