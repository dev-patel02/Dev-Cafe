import { DataTypes } from "sequelize";
// import { sequelize } from "../config/index.js";

const Orders = (sequelize) => {
  sequelize.define(
    "orders",
    {
      id: {
        type: DataTypes.INTEGER(2),
        primaryKey: true,
        autoIncrement: true,
        allowNull: false,
      },
      product_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      tenant_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      user_id: {
        type: DataTypes.INTEGER,
        allowNull: false,
      },
      date: {
        type: DataTypes.DATEONLY,
        allowNull: false,
      },
      quantity: {
        type: DataTypes.INTEGER(4),
        allowNull: false,
      },
      total_amount: {
        type: DataTypes.INTEGER(8),
        allowNull: false,
        comment: "from orderd_product",
      },
    },
    {
      paranoid: true,
      
    }
  );
};

export default Orders;

