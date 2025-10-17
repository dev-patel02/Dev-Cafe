import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { Tenant, User, Products, Orders } from "../models/association.js";
import Sequelize from "sequelize";
import { sequelize } from "../config/index.js";
let tables = [User, Products, Orders]
let signUp = async (req, res) => {
  try {
    let data = req.body;
    // data.password = await bcrypt.hash(data.password, 10);

    let info = await Tenant.create(data, { logging: console.log });
    // let random = (Math.random() * 100).toString(36);
    const dbname = `Qbot_tenant_${(data.name).replaceAll(" ","_")}`;
    console.log(dbname)
    let db = await sequelize.query(`CREATE DATABASE IF NOT EXISTS ${dbname}`);

    const instance = new Sequelize(
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
    
    for (const table of tables) {
        // const temp = await table(instance);
        await instance.sync();
    }

    res.status(200).json({
      log: "Tenat SucessFully Created",
      data: info,
      database : db 
    });
  } catch (error) {
    res.status(500).json({
      error: error.message ?? error,
    });
  }
};

let login = async (req, res) => {
  try {
    let { email, password } = req.body;
    const found = await User.findOne({
      where: {
        email: email,
      },
    });
    if (!found) {
      res.status(500).json({
        log: "Invalid Email!! Try Again",
      });
    }
    let match = await bcrypt.compare(password, found.password);
    if (!match) {
      res.status(500).json({
        log: "Invalid Password!!Try Again",
      });
    }

    let paylode = {
      id: found.user_id,
      role: found.role_id,
      status: found.status,
    };
    let token = jwt.sign(paylode, process.env.JWT_TOKEN, {
      expiresIn: process.env.JWT_EXPIRE,
    });
    res.status(200).send({
      log: `Successfully Logged In '${
        found.first_name + " " + found.last_name
      }' :) `,
      token: token,
    });
  } catch (error) {
    res.status(500).json({
      // error: error.message,
      error: error,
    });
  }
};

let getProducts = async (req, res) => {
  try {
    let data = await Products.findAll({
      attributes: ["name", "details", "image"],
      include: {
        as: "attributes",
        model: Attributes,
        attributes: ["name"],
        include: {
          as: "values",
          model: Varient,
          attributes: ["name", "price", "qunatity"],
        },
      },
    });
    res.status(200).json({
      log: "All Products with Available ",
      data: data,
    });
  } catch (error) {
    res.status(500).json({
      error: error.message ?? error,
    });
  }
};

// Add
let addVarients = async (req, res) => {
  try {
    let data = req.body;
    let found = await Attributes.findByPk(data.varient_id);
    if (!found) {
      res.status(500).json({
        log: `Attribute Not found At ypur Specific id ${data.product_id}`,
      });
    }
    // value, price, quantity
    let info = await Varient.create(data);
    res.status(200).json({
      log: `'${info.name}' Varient Is Created for '${found.varient_id}'`,
      data: info,
    });
  } catch (error) {
    res.status(500).json({
      log: error.message ?? error,
    });
  }
};

const exportedModules = {
  signUp,
  login,

  //get
  getProducts,

  //add
  addVarients,
};

export default exportedModules;
