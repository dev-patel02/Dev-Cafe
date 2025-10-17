import { sequelize } from "../config/index.js";
import { DataTypes } from "sequelize";

const Tenents = sequelize.define(
  "tenents",
  {
    tenant_id: {
      type: DataTypes.INTEGER(3),
      primaryKey: true,
      autoIncrement: true,
    },
    name: {
      type: DataTypes.STRING(30),
      allowNull: false,
    },
    subdomain: {
      type: DataTypes.STRING,
      allowNull: false,
      unique: true,
      unique: {
        msg: "This SubDomain Is Reserved!! Try Another One",
      },
    },
    status: {
      type: DataTypes.ENUM("Active", "Inactive"),
      defaultValue: "Active",
      allowNull: false,
    },
    email: {
      type: DataTypes.STRING(30),
      validate: {
        isEmail: true,
        isEmail: {
          msg: "Invalid Email Format",
        },
      },
      allowNull: false,
      comment : "Admin"
    },
  },
  {
    initialAutoIncrement: 101,
    paranoid: true,
  }
);

export default Tenents;
