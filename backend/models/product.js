import { DataTypes } from "sequelize";
import { sequelize } from "../config/index.js";

const Products = sequelize.define(
  "products",
  {
    product_id: {
      type: DataTypes.INTEGER(5),
      primaryKey: true,
      autoIncrement: true,
      allowNull: false,
    },
    user_id: {
        type: DataTypes.INTEGER(4),
        allowNull: true,
    },
    name: {
        type: DataTypes.STRING(20),
        allowNull: false,
    },
    details: {
        type: DataTypes.TEXT,
        allowNull: false,
    },
    price: {
      type: DataTypes.DECIMAL(7,2),
      allowNull: false,
    },
  },
  {
    paranoid : true,
    initialAutoIncrement: 1,
  }
);
export default Products;
