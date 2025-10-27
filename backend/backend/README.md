# Dev-s-Cafe
The MERN Project With The Implementation of SaaS Multi Tenant Workflow


i want to create an SaaS application tenant based architecture MERN Project but i am stuck on  the feature role based access basically i have idea in my mind about I Will be creating Restaurant based Saas application  where restaurant can sign up by master and take subscription plan monthly and i have decided some models for master as well as tenant like master have one master (static master) and then tenant (restaurant info, domainname , subscribed plan, etc...) then subscription plans and then global setting like two step verification when login and then tenant can have  sparate db and they have model like menu , catagory , order, biiling, feedback , users, roles(admin manager chef waiter) and the database can create dynamically by sequelize as well as their tenant schema so master and tenant have saparate dababase and i want it like just backend for now like dotenv express nodemon sequlize mysql and jsonwebtoken cors add bcrypt nodemailer and before all that i want to know about role based access in tenant how it works 


=====
***MOdules***
=====






Excellent project idea! Let me explain how Role-Based Access Control (RBAC) works in a multi-tenant SaaS architecture and provide you with a complete implementation guide.

## Understanding RBAC in Multi-Tenant Architecture

### Conceptual Overview

```
Master Database (Shared)
├── Master Admin (Super Admin)
├── Tenants (Restaurants)
├── Subscription Plans
└── Global Settings

Tenant Database (Per Restaurant)
├── Users (with assigned roles)
├── Roles (Admin, Manager, Chef, Waiter)
├── Permissions (mapped to roles)
└── Business Data (Menu, Orders, etc.)
```

## Complete Backend Implementation

Let me provide you with a full implementation structure:

### 1. Project Structure

```
restaurant-saas/
├── config/
│   ├── database.js
│   ├── masterDb.js
│   └── tenantDb.js
├── middleware/
│   ├── auth.js
│   ├── rbac.js
│   └── tenantResolver.js
├── models/
│   ├── master/
│   │   ├── Master.js
│   │   ├── Tenant.js
│   │   └── SubscriptionPlan.js
│   └── tenant/
│       ├── User.js
│       ├── Role.js
│       ├── Permission.js
│       ├── Menu.js
│       ├── Category.js
│       ├── Order.js
│       └── Feedback.js
├── controllers/
│   ├── master/
│   └── tenant/
├── routes/
│   ├── master/
│   └── tenant/
├── utils/
│   ├── dbManager.js
│   └── tokenManager.js
├── .env
├── server.js
└── package.json
```

### 2. Package.json

```json
{
  "name": "restaurant-saas",
  "version": "1.0.0",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "dev": "nodemon server.js"
  },
  "dependencies": {
    "express": "^4.18.2",
    "sequelize": "^6.33.0",
    "mysql2": "^3.6.0",
    "jsonwebtoken": "^9.0.2",
    "bcrypt": "^5.1.1",
    "cors": "^2.8.5",
    "dotenv": "^16.3.1",
    "nodemailer": "^6.9.4",
    "helmet": "^7.0.0"
  },
  "devDependencies": {
    "nodemon": "^3.0.1"
  }
}
```

### 3. Environment Configuration (.env)

```env
# Server Configuration
PORT=5000
NODE_ENV=development

# Master Database
MASTER_DB_HOST=localhost
MASTER_DB_USER=root
MASTER_DB_PASSWORD=yourpassword
MASTER_DB_NAME=restaurant_saas_master
MASTER_DB_PORT=3306

# JWT Configuration
JWT_SECRET=your_super_secret_key_here
JWT_EXPIRE=7d

# Email Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your_email@gmail.com
SMTP_PASS=your_app_password
```

### 4. Database Configuration

**config/database.js**
```javascript
const { Sequelize } = require('sequelize');

class DatabaseManager {
    constructor() {
        this.tenantConnections = new Map();
    }

    // Create master database connection
    createMasterConnection() {
        return new Sequelize(
            process.env.MASTER_DB_NAME,
            process.env.MASTER_DB_USER,
            process.env.MASTER_DB_PASSWORD,
            {
                host: process.env.MASTER_DB_HOST,
                port: process.env.MASTER_DB_PORT,
                dialect: 'mysql',
                logging: false,
                pool: {
                    max: 5,
                    min: 0,
                    acquire: 30000,
                    idle: 10000
                }
            }
        );
    }

    // Create or get tenant database connection
    async getTenantConnection(tenantId) {
        if (this.tenantConnections.has(tenantId)) {
            return this.tenantConnections.get(tenantId);
        }

        const dbName = `tenant_${tenantId}`;
        const connection = new Sequelize(
            dbName,
            process.env.MASTER_DB_USER,
            process.env.MASTER_DB_PASSWORD,
            {
                host: process.env.MASTER_DB_HOST,
                port: process.env.MASTER_DB_PORT,
                dialect: 'mysql',
                logging: false,
                pool: {
                    max: 5,
                    min: 0,
                    acquire: 30000,
                    idle: 10000
                }
            }
        );

        this.tenantConnections.set(tenantId, connection);
        return connection;
    }

    // Create new tenant database
    async createTenantDatabase(tenantId) {
        const dbName = `tenant_${tenantId}`;
        const masterConnection = this.createMasterConnection();
        
        try {
            await masterConnection.query(`CREATE DATABASE IF NOT EXISTS ${dbName}`);
            console.log(`Database ${dbName} created successfully`);
            
            // Get tenant connection and sync models
            const tenantConnection = await this.getTenantConnection(tenantId);
            await this.initializeTenantSchema(tenantConnection);
            
            return true;
        } catch (error) {
            console.error('Error creating tenant database:', error);
            throw error;
        }
    }

    // Initialize tenant schema with all models
    async initializeTenantSchema(connection) {
        const models = require('../models/tenant');
        
        // Initialize all models
        Object.values(models).forEach(model => {
            model.init(connection);
        });

        // Setup associations
        this.setupTenantAssociations(models);

        // Sync database
        await connection.sync({ force: false });

        // Seed default roles and permissions
        await this.seedDefaultRolesAndPermissions(models);
    }

    // Setup model associations for tenant
    setupTenantAssociations(models) {
        const { User, Role, Permission, Menu, Category, Order } = models;

        // User-Role relationship
        User.belongsTo(Role, { foreignKey: 'roleId' });
        Role.hasMany(User, { foreignKey: 'roleId' });

        // Role-Permission relationship (many-to-many)
        Role.belongsToMany(Permission, { 
            through: 'RolePermissions',
            foreignKey: 'roleId'
        });
        Permission.belongsToMany(Role, { 
            through: 'RolePermissions',
            foreignKey: 'permissionId'
        });

        // Menu-Category relationship
        Category.hasMany(Menu, { foreignKey: 'categoryId' });
        Menu.belongsTo(Category, { foreignKey: 'categoryId' });

        // Order relationships
        Order.belongsTo(User, { foreignKey: 'userId' });
        User.hasMany(Order, { foreignKey: 'userId' });
    }

    // Seed default roles and permissions
    async seedDefaultRolesAndPermissions(models) {
        const { Role, Permission } = models;

        // Default permissions
        const permissions = [
            // Menu permissions
            { name: 'menu.create', description: 'Create menu items' },
            { name: 'menu.read', description: 'View menu items' },
            { name: 'menu.update', description: 'Update menu items' },
            { name: 'menu.delete', description: 'Delete menu items' },
            
            // Order permissions
            { name: 'order.create', description: 'Create orders' },
            { name: 'order.read', description: 'View orders' },
            { name: 'order.update', description: 'Update orders' },
            { name: 'order.delete', description: 'Delete orders' },
            
            // User management permissions
            { name: 'user.create', description: 'Create users' },
            { name: 'user.read', description: 'View users' },
            { name: 'user.update', description: 'Update users' },
            { name: 'user.delete', description: 'Delete users' },
            
            // Billing permissions
            { name: 'billing.create', description: 'Create bills' },
            { name: 'billing.read', description: 'View bills' },
            { name: 'billing.update', description: 'Update bills' },
            
            // Reports permissions
            { name: 'reports.view', description: 'View reports' },
            { name: 'reports.export', description: 'Export reports' }
        ];

        // Create permissions
        const createdPermissions = await Permission.bulkCreate(permissions, {
            ignoreDuplicates: true
        });

        // Default roles with their permissions
        const rolesWithPermissions = [
            {
                name: 'admin',
                description: 'Restaurant Administrator',
                permissions: permissions.map(p => p.name) // All permissions
            },
            {
                name: 'manager',
                description: 'Restaurant Manager',
                permissions: [
                    'menu.read', 'menu.update',
                    'order.read', 'order.update',
                    'user.read', 'user.create', 'user.update',
                    'billing.read', 'billing.create', 'billing.update',
                    'reports.view', 'reports.export'
                ]
            },
            {
                name: 'chef',
                description: 'Kitchen Chef',
                permissions: [
                    'menu.read',
                    'order.read', 'order.update'
                ]
            },
            {
                name: 'waiter',
                description: 'Service Staff',
                permissions: [
                    'menu.read',
                    'order.create', 'order.read', 'order.update',
                    'billing.create', 'billing.read'
                ]
            }
        ];

        // Create roles and assign permissions
        for (const roleData of rolesWithPermissions) {
            const [role] = await Role.findOrCreate({
                where: { name: roleData.name },
                defaults: {
                    description: roleData.description
                }
            });

            // Assign permissions to role
            const rolePermissions = await Permission.findAll({
                where: {
                    name: roleData.permissions
                }
            });

            await role.setPermissions(rolePermissions);
        }

        console.log('Default roles and permissions seeded successfully');
    }
}

module.exports = new DatabaseManager();
```

### 5. Master Models

**models/master/Tenant.js**
```javascript
const { DataTypes } = require('sequelize');

class Tenant {
    static init(sequelize) {
        return sequelize.define('Tenant', {
            id: {
                type: DataTypes.UUID,
                defaultValue: DataTypes.UUIDV4,
                primaryKey: true
            },
            restaurantName: {
                type: DataTypes.STRING,
                allowNull: false
            },
            domainName: {
                type: DataTypes.STRING,
                unique: true,
                allowNull: false
            },
            email: {
                type: DataTypes.STRING,
                unique: true,
                allowNull: false,
                validate: {
                    isEmail: true
                }
            },
            phone: {
                type: DataTypes.STRING,
                allowNull: false
            },
            address: {
                type: DataTypes.TEXT
            },
            subscriptionPlanId: {
                type: DataTypes.INTEGER,
                references: {
                    model: 'SubscriptionPlans',
                    key: 'id'
                }
            },
            subscriptionStatus: {
                type: DataTypes.ENUM('active', 'inactive', 'suspended', 'trial'),
                defaultValue: 'trial'
            },
            subscriptionEndDate: {
                type: DataTypes.DATE
            },
            isActive: {
                type: DataTypes.BOOLEAN,
                defaultValue: true
            },
            settings: {
                type: DataTypes.JSON,
                defaultValue: {
                    twoFactorAuth: false,
                    emailNotifications: true
                }
            }
        }, {
            timestamps: true,
            tableName: 'tenants'
        });
    }
}

module.exports = Tenant;
```

### 6. Tenant Models

**models/tenant/User.js**
```javascript
const { DataTypes } = require('sequelize');
const bcrypt = require('bcrypt');

class User {
    static init(sequelize) {
        const User = sequelize.define('User', {
            id: {
                type: DataTypes.UUID,
                defaultValue: DataTypes.UUIDV4,
                primaryKey: true
            },
            firstName: {
                type: DataTypes.STRING,
                allowNull: false
            },
            lastName: {
                type: DataTypes.STRING,
                allowNull: false
            },
            email: {
                type: DataTypes.STRING,
                unique: true,
                allowNull: false,
                validate: {
                    isEmail: true
                }
            },
            password: {
                type: DataTypes.STRING,
                allowNull: false
            },
            phone: {
                type: DataTypes.STRING
            },
            roleId: {
                type: DataTypes.UUID,
                allowNull: false,
                references: {
                    model: 'Roles',
                    key: 'id'
                }
            },
            isActive: {
                type: DataTypes.BOOLEAN,
                defaultValue: true
            },
            lastLogin: {
                type: DataTypes.DATE
            },
            twoFactorSecret: {
                type: DataTypes.STRING
            },
            twoFactorEnabled: {
                type: DataTypes.BOOLEAN,
                defaultValue: false
            }
        }, {
            timestamps: true,
            tableName: 'users',
            hooks: {
                beforeCreate: async (user) => {
                    user.password = await bcrypt.hash(user.password, 10);
                },
                beforeUpdate: async (user) => {
                    if (user.changed('password')) {
                        user.password = await bcrypt.hash(user.password, 10);
                    }
                }
            }
        });

        // Instance methods
        User.prototype.validatePassword = async function(password) {
            return bcrypt.compare(password, this.password);
        };

        User.prototype.hasPermission = async function(permissionName) {
            const role = await this.getRole({
                include: [{
                    model: sequelize.models.Permission,
                    where: { name: permissionName }
                }]
            });

            return role && role.Permissions && role.Permissions.length > 0;
        };

        return User;
    }
}

module.exports = User;
```

**models/tenant/Role.js**
```javascript
const { DataTypes } = require('sequelize');

class Role {
    static init(sequelize) {
        return sequelize.define('Role', {
            id: {
                type: DataTypes.UUID,
                defaultValue: DataTypes.UUIDV4,
                primaryKey: true
            },
            name: {
                type: DataTypes.STRING,
                unique: true,
                allowNull: false
            },
            description: {
                type: DataTypes.STRING
            },
            isActive: {
                type: DataTypes.BOOLEAN,
                defaultValue: true
            }
        }, {
            timestamps: true,
            tableName: 'roles'
        });
    }
}

module.exports = Role;
```

**models/tenant/Permission.js**
```javascript
const { DataTypes } = require('sequelize');

class Permission {
    static init(sequelize) {
        return sequelize.define('Permission', {
            id: {
                type: DataTypes.UUID,
                defaultValue: DataTypes.UUIDV4,
                primaryKey: true
            },
            name: {
                type: DataTypes.STRING,
                unique: true,
                allowNull: false
            },
            description: {
                type: DataTypes.STRING
            }
        }, {
            timestamps: true,
            tableName: 'permissions'
        });
    }
}

module.exports = Permission;
```

### 7. Authentication & RBAC Middleware

**middleware/auth.js**
```javascript
const jwt = require('jsonwebtoken');
const dbManager = require('../config/database');

exports.authenticate = async (req, res, next) => {
    try {
        const token = req.header('Authorization')?.replace('Bearer ', '');

        if (!token) {
            throw new Error();
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        
        // Get tenant connection
        const tenantConnection = await dbManager.getTenantConnection(decoded.tenantId);
        const User = require('../models/tenant/User');
        User.init(tenantConnection);

        const user = await User.findOne({
            where: {
                id: decoded.userId,
                isActive: true
            },
            include: [{
                model: tenantConnection.models.Role,
                include: [{
                    model: tenantConnection.models.Permission
                }]
            }]
        });

        if (!user) {
            throw new Error();
        }

        req.user = user;
        req.tenantId = decoded.tenantId;
        req.tenantConnection = tenantConnection;
        
        next();
    } catch (error) {
        res.status(401).json({ error: 'Please authenticate' });
    }
};
```

**middleware/rbac.js**
```javascript
exports.authorize = (...permissions) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            const userPermissions = req.user.Role.Permissions.map(p => p.name);
            
            const hasPermission = permissions.some(permission => 
                userPermissions.includes(permission)
            );

            if (!hasPermission) {
                return res.status(403).json({ 
                    error: 'Insufficient permissions',
                    required: permissions,
                    userPermissions: userPermissions
                });
            }

            next();
        } catch (error) {
            res.status(500).json({ error: 'Error checking permissions' });
        }
    };
};

exports.authorizeRole = (...roles) => {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                return res.status(401).json({ error: 'Authentication required' });
            }

            if (!roles.includes(req.user.Role.name)) {
                return res.status(403).json({ 
                    error: 'Insufficient role privileges',
                    required: roles,
                    userRole: req.user.Role.name
                });
            }

            next();
        } catch (error) {
            res.status(500).json({ error: 'Error checking role' });
        }
    };
};
```

### 8. Example Controller with RBAC

**controllers/tenant/menuController.js**
```javascript
exports.createMenuItem = async (req, res) => {
    try {
        const Menu = req.tenantConnection.models.Menu;
        const menuItem = await Menu.create(req.body);
        
        res.status(201).json({
            success: true,
            data: menuItem
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
};

exports.getMenuItems = async (req, res) => {
    try {
        const Menu = req.tenantConnection.models.Menu;
        const menuItems = await Menu.findAll({
            include: [{
                model: req.tenantConnection.models.Category
            }]
        });
        
        res.status(200).json({
            success: true,
            data: menuItems
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
};

exports.updateMenuItem = async (req, res) => {
    try {
        const Menu = req.tenantConnection.models.Menu;
        const menuItem = await Menu.findByPk(req.params.id);
        
        if (!menuItem) {
            return res.status(404).json({
                success: false,
                error: 'Menu item not found'
            });
        }

        await menuItem.update(req.body);
        
        res.status(200).json({
            success: true,
            data: menuItem
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
};

exports.deleteMenuItem = async (req, res) => {
    try {
        const Menu = req.tenantConnection.models.Menu;
        const menuItem = await Menu.findByPk(req.params.id);
        
        if (!menuItem) {
            return res.status(404).json({
                success: false,
                error: 'Menu item not found'
            });
        }

        await menuItem.destroy();
        
        res.status(200).json({
            success: true,
            message: 'Menu item deleted successfully'
        });
    } catch (error) {
        res.status(400).json({
            success: false,
            error: error.message
        });
    }
};
```

### 9. Routes with RBAC

**routes/tenant/menuRoutes.js**
```javascript
const router = require('express').Router();
const menuController = require('../../controllers/tenant/menuController');
const { authenticate } = require('../../middleware/auth');
const { authorize, authorizeRole } = require('../../middleware/rbac');

// All routes require authentication
router.use(authenticate);

// Public routes (all authenticated users)
router.get('/', authorize('menu.read'), menuController.getMenuItems);

// Admin and Manager only
router.post('/', 
    authorize('menu.create'), 
    menuController.createMenuItem
);

router.put('/:id', 
    authorize('menu.update'), 
    menuController.updateMenuItem
);

// Admin only
router.delete('/:id', 
    authorizeRole('admin'), 
    menuController.deleteMenuItem
);

module.exports = router;
```

### 10. Main Server File

**server.js**
```javascript
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');

const app = express();

// Middleware
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Initialize database
const dbManager = require('./config/database');

// Routes
app.use('/api/master', require('./routes/master'));
app.use('/api/tenant', require('./routes/tenant'));

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        success: false,
        error: 'Something went wrong!'
    });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
```

## How RBAC Works in This Architecture:

### 1. **Authentication Flow:**
```javascript
// Login endpoint returns JWT with tenantId and userId
{
    "token": "JWT_TOKEN",
    "user": {
        "id": "user_uuid",
        "role": "manager",
        "permissions": ["menu.read", "menu.update", ...]
    }
}
```

### 2. **Authorization Check:**
- Each request includes JWT token
- Middleware extracts tenantId from token
- Connects to correct tenant database
- Loads user with role and permissions
- Checks if user has required permission/role

### 3. **Permission Hierarchy:**
```
Admin → All permissions
Manager → Most permissions (except user deletion, critical settings)
Chef → Kitchen-related permissions
Waiter → Order and billing permissions
```

### 4. **Usage Examples:**

```javascript
// Route-level permission check
router.post('/menu', 
    authenticate,
    authorize('menu.create'), // Check specific permission
    controller.create
);

// Controller-level check
if (await req.user.hasPermission('reports.export')) {
    // Allow export
}

// Role-based check
router.delete('/users/:id',
    authenticate,
    authorizeRole('admin'), // Only admin role
    controller.deleteUser
);
```

## Key Features of This Implementation:

1. **Dynamic Tenant Database Creation**: Each restaurant gets its own database
2. **Flexible Permission System**: Granular permissions that can be assigned to roles
3. **JWT-based Authentication**: Stateless authentication with tenant context
4. **Middleware-based Authorization**: Clean, reusable permission checks
5. **Role Hierarchy**: Predefined roles with specific permission sets
6. **Scalable Architecture**: Can handle multiple tenants with isolated data

This architecture ensures complete data isolation between tenants while providing flexible role-based access control within each tenant's context.