import Master from "./master.js";
import Orders from "./orders.js";
import Products from "./product.js";
import Tenant from "./tenants.js";
import User from "./user.js";

// User & products 
User.hasMany(Products, { foreignKey: "user_id" });
Products.belongsTo(User, { foreignKey: "user_id" });

// Tenents & User
Tenant.hasMany(User, { foreignKey: "tenant_id" });
User.belongsTo(Tenant, { foreignKey: "tenant_id" });

// Products & Orders
Products.hasMany(Orders, { foreignKey: "product_id" });
Orders.belongsTo(Products, { foreignKey: "product_id" });

export { Master, Orders, Products, Tenant, User };
