
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const app = express();
app.use(express.json({ limit: "32kb" }));

const PORT = process.env.PORT || 3000;
const JWT_SECRET =
  process.env.JWT_SECRET || crypto.randomBytes(32).toString("hex");

// Demo storage: accounts and tokens reset when the server restarts.
const users = new Map();
let nextUserId = 1001;

const outfits = [
  {
    id: 10001,
    name: "Classic Outfit",
    outfitType: "Avatar",
    isEditable: true,
    assets: [
      { id: 101, name: "Classic Shirt", assetType: "Shirt" },
      { id: 102, name: "Classic Pants", assetType: "Pants" }
    ]
  },
  {
    id: 10002,
    name: "Casual Outfit",
    outfitType: "Avatar",
    isEditable: true,
    assets: [
      { id: 201, name: "Casual T-Shirt", assetType: "TShirt" },
      { id: 202, name: "Casual Trousers", assetType: "Pants" }
    ]
  }
];

function sendError(res, status, code, message) {
  return res.status(status).json({
    errors: [{ code, message }]
  });
}

function publicUser(user) {
  return {
    id: user.id,
    name: user.username,
    displayName: user.displayName
  };
}

// Require a valid token issued by THIS demo server.
function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const [scheme, token] = header.split(" ");

  if (scheme !== "Bearer" || !token) {
    return sendError(res, 401, 0, "Authentication required.");
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);
    const user = users.get(payload.sub);

    if (!user) {
      return sendError(res, 401, 0, "User not found.");
    }

    req.user = user;
    next();
  } catch {
    return sendError(res, 401, 0, "Invalid or expired token.");
  }
}

// Health check
app.get("/", (req, res) => {
  res.json({
    name: "Custom Avatar API",
    version: "1.0.0",
    status: "OK"
  });
});

// Register a demo account
app.post("/api/auth/register", async (req, res) => {
  try {
    const { username, password } = req.body || {};

    if (
      typeof username !== "string" ||
      !/^[a-zA-Z0-9_]{3,20}$/.test(username)
    ) {
      return sendError(
        res, 400, 1,
        "Username must be 3-20 letters, numbers or underscores."
      );
    }

    if (typeof password !== "string" || password.length < 8 ||
        password.length > 128) {
      return sendError(
        res, 400, 2,
        "Password must be between 8 and 128 characters."
      );
    }

    const normalized = username.toLowerCase();

    if ([...users.values()].some(
      user => user.username.toLowerCase() === normalized
    )) {
      return sendError(res, 409, 3, "Username already exists.");
    }

    const user = {
      id: String(nextUserId++),
      username,
      displayName: username,
      passwordHash: await bcrypt.hash(password, 12),
      avatar: {
        userId: null,
        scales: {
          height: 1,
          width: 1,
          head: 1,
          depth: 1,
          proportion: 0,
          bodyType: 0
        },
        assets: [
          { id: 101, name: "Classic Shirt", assetType: "Shirt" },
          { id: 102, name: "Classic Pants", assetType: "Pants" }
        ],
        colors: {
          headColor: "#F2C9A5",
          torsoColor: "#3366CC",
          leftArmColor: "#F2C9A5",
          rightArmColor: "#F2C9A5",
          leftLegColor: "#3366CC",
          rightLegColor: "#3366CC"
        }
      }
    };

    user.avatar.userId = Number(user.id);
    users.set(user.id, user);

    return res.status(201).json({
      success: true,
      user: publicUser(user)
    });
  } catch (error) {
    console.error(error);
    return sendError(res, 500, 500, "Internal server error.");
  }
});

// Log in to a demo account
app.post("/api/auth/login", async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== "string" ||
      typeof password !== "string") {
    return sendError(res, 400, 1, "Username and password are required.");
  }

  const user = [...users.values()].find(
    item => item.username.toLowerCase() === username.toLowerCase()
  );

  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return sendError(res, 401, 2, "Invalid username or password.");
  }

  const token = jwt.sign(
    { sub: user.id },
    JWT_SECRET,
    { expiresIn: "1h", issuer: "custom-avatar-api" }
  );

  return res.json({
    token,
    tokenType: "Bearer",
    expiresIn: 3600,
    user: publicUser(user)
  });
});

// Get the logged-in demo user
app.get("/api/users/me", authenticate, (req, res) => {
  res.json({
    ...publicUser(req.user),
    description: "",
    created: "2026-01-01T00:00:00.000Z"
  });
});

// List sample outfits
app.get("/v1/users/:userId/outfits", (req, res) => {
  const userId = Number(req.params.userId);

  if (!Number.isSafeInteger(userId) || userId < 1) {
    return sendError(res, 400, 1, "Invalid user ID.");
  }

  res.json({
    data: outfits.map(outfit => ({
      ...outfit,
      creator: {
        id: userId,
        name: "DemoUser"
      }
    })),
    total: outfits.length
  });
});

// Get the authenticated user's avatar configuration
app.get("/v1/avatar", authenticate, (req, res) => {
  res.json(req.user.avatar);
});

// Get the avatar configuration for a particular demo user
app.get("/v1/users/:userId/avatar", (req, res) => {
  const user = users.get(String(req.params.userId));

  if (!user) {
    return sendError(res, 404, 1, "User not found.");
  }

  res.json(user.avatar);
});

// List clothing and accessory assets in the sample catalog
app.get("/v1/avatar/assets", (req, res) => {
  const assets = outfits.flatMap(outfit => outfit.assets);

  res.json({
    data: assets,
    total: assets.length
  });
});

// Update the authenticated user's avatar using catalog assets
app.patch("/v1/avatar/assets", authenticate, (req, res) => {
  const { assets } = req.body || {};

  if (!Array.isArray(assets) || assets.length > 50) {
    return sendError(res, 400, 1, "Provide an array of up to 50 assets.");
  }

  const catalog = outfits.flatMap(outfit => outfit.assets);
  const validated = [];

  for (const item of assets) {
    if (!item || !Number.isSafeInteger(item.id)) {
      return sendError(res, 400, 2, "Every asset needs a numeric ID.");
    }

    const found = catalog.find(asset => asset.id === item.id);

    if (!found) {
      return sendError(res, 400, 3, "Asset is not in the demo catalog.");
    }

    validated.push({ ...found });
  }

  req.user.avatar.assets = validated;

  res.json({
    success: true,
    avatar: req.user.avatar
  });
});

// JSON 404 handler
app.use((req, res) => {
  sendError(res, 404, 404, "Endpoint not found.");
});

// Generic error handler
app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err instanceof SyntaxError && err.status === 400) {
    return sendError(res, 400, 1, "Invalid JSON request body.");
  }

  console.error(err);
  return sendError(res, 500, 500, "Internal server error.");
});

app.listen(PORT, () => {
  console.log(`Custom Avatar API running on port ${PORT}`);
  console.log(`Test locally: http://localhost:${PORT}`);
});
