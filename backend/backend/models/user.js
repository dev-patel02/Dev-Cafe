import { sequelize } from "../config/index.js";
import { DataTypes } from "sequelize";

const User = sequelize.define(
  "users",
  {
    user_id: {
      type: DataTypes.INTEGER(3),
      primaryKey: true,
      autoIncrement: true,
    },
    tenant_id: {
      type: DataTypes.INTEGER(3),
      allowNull: false,
    },
    name: {
      type: DataTypes.STRING(30),
      allowNull: false,
    },
    gender: {
      type: DataTypes.ENUM("Male", "Female"),
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
    initialAutoIncrement: 1001,
  } 
);

export default User;
