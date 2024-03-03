import mongoose from "mongoose";
import express from "express";
import "dotenv/config";

import { DB_NAME } from "./contants.js";
import { connectDB } from "./db/index.js";

connectDB();
