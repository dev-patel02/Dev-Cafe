import Sequelize from "sequelize";
import dotenv from "dotenv";

dotenv.config({ quiet: true });

// Master Instance
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
    // logging: false,
  }
);

// Tenant Instance
const tenantInstance = (dbname) => {
  let sequelize = new Sequelize(
    dbname,
    process.env.DB_USER,
    process.env.DB_PASSWORD,
    {
      host: process.env.DB_HOST,
      dialect: "mysql",
      define: {
        timestamps: true,
        freezeTableName: true,
      },
    }
  );
  return sequelize;
};

let connectDB = async () => {
  await sequelize.authenticate();
  // await sequelize.sync({ alter: true });
};

export { sequelize, connectDB, tenantInstance };
