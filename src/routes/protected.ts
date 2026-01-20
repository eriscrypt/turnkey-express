import { Router, Response } from "express";
import {
  turnkeyAuthMiddleware,
  AuthenticatedRequest,
} from "../middleware/turnkeyAuth.js";

const router = Router();

// Get current user info
router.get(
  "/me",
  turnkeyAuthMiddleware,
  (req: AuthenticatedRequest, res: Response) => {
    res.json({
      success: true,
      user: req.user,
    });
  }
);

// Example: Get user's wallet data
router.get(
  "/wallet",
  turnkeyAuthMiddleware,
  async (req: AuthenticatedRequest, res: Response) => {
    // Here you can use req.user.userId to fetch wallet data
    // from your database or Turnkey API
    res.json({
      success: true,
      userId: req.user?.userId,
      message: "Implement your wallet logic here",
    });
  }
);

// Example: Protected action
router.post(
  "/action",
  turnkeyAuthMiddleware,
  async (req: AuthenticatedRequest, res: Response) => {
    const { action } = req.body;

    // Perform some protected action
    res.json({
      success: true,
      userId: req.user?.userId,
      action,
      message: "Action performed successfully",
    });
  }
);

export default router;
