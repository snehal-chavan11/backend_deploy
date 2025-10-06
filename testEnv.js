import dotenv from "dotenv";

dotenv.config();

console.log("Mongo URI:", process.env.MONGO_URI);
console.log("JWT Secret:", process.env.JWT_SECRET);
