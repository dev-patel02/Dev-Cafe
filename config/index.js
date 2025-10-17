import Sequelize from "sequelize";
import dotenv from "dotenv";
dotenv.config({quiet: true});

const sequelize = new Sequelize(
  process.env.DB_NAME,
  process.env.DB_USER,
  process.env.DB_PASSWORD,
  {
    host: process.env.DB_HOST,
    dialect: "mysql",
    define: {
      timestamps: true,
      freezeTableName: true,
    },
    logging: false,
  }
);

let connectDB = async () => {
  await sequelize.authenticate();
  // await sequelize.sync({ alter: true });
};

export { sequelize, connectDB };
