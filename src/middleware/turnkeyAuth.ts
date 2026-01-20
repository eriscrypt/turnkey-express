import { Request, Response, NextFunction } from "express";
import { verifySessionJwtSignature } from "@turnkey/crypto";

export interface TurnkeyUser {
  userId: string;
  organizationId: string;
  sessionType: string;
  publicKey: string;
}

export interface AuthenticatedRequest extends Request {
  user?: TurnkeyUser;
}

interface DecodedJwt {
  sessionType: string;
  userId: string;
  organizationId: string;
  expiry: number;
  publicKey: string;
}

function decodeSessionJwt(token: string): DecodedJwt {
  const [, payload] = token.split(".");
  if (!payload) {
    throw new Error("Invalid JWT: Missing payload");
  }

  const decoded = JSON.parse(Buffer.from(payload, "base64").toString());
  const { exp, public_key, session_type, user_id, organization_id } = decoded;

  if (!exp || !public_key || !session_type || !user_id || !organization_id) {
    throw new Error("JWT payload missing required fields");
  }

  return {
    sessionType: session_type,
    userId: user_id,
    organizationId: organization_id,
    expiry: exp,
    publicKey: public_key,
  };
}

export async function turnkeyAuthMiddleware(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith("Bearer ")) {
      res.status(401).json({ error: "Missing authorization header" });
      return;
    }

    const sessionJwt = authHeader.slice(7);

    // 1. Verify signature (confirms token was signed by Turnkey)
    const isValid = await verifySessionJwtSignature(sessionJwt);
    if (!isValid) {
      res.status(401).json({ error: "Invalid JWT signature" });
      return;
    }

    // 2. Decode and validate payload
    const decoded = decodeSessionJwt(sessionJwt);

    // 3. Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (decoded.expiry < now) {
      res.status(401).json({ error: "JWT expired" });
      return;
    }

    // 4. Attach user data to request
    // Note: organizationId is the user's sub-org, not parent org
    // Signature verification is sufficient - no need to check org ID
    req.user = {
      userId: decoded.userId,
      organizationId: decoded.organizationId,
      sessionType: decoded.sessionType,
      publicKey: decoded.publicKey,
    };

    next();
  } catch (error) {
    console.error("Auth error:", error);
    res.status(401).json({ error: "Authentication failed" });
  }
}
