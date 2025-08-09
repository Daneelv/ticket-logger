import { logEvent } from "@/utils/sentry";
import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";

const secret = new TextEncoder().encode(process.env.AUTH_SECRET);
const cookieName = "auth_token";

// Encrypt and sign token
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function signAuthToken(payload: any) {
  try {
    const token = await new SignJWT(payload)
      .setProtectedHeader({
        alg: "HS256",
      })
      .setIssuedAt()
      .setExpirationTime("7d")
      .sign(secret);

    return token;
  } catch (error) {
    logEvent("Token signing Failed", "auth", { payload }, "error", error);
    throw new Error("Token signing failed");
  }
}

// decrypt and verify token
export async function verifyAuthToken<T>(token: string): Promise<T> {
  try {
    const { payload } = await jwtVerify(token, secret);
    return payload as T;
  } catch (error) {
    logEvent(
      "Token decryption Failed",
      "auth",
      { tokenSnippet: token.slice(0, 10) },
      "error",
      error
    );
    throw new Error("Token verification failed");
  }
}

// Set auth cookie
export async function setAuthCookie(token: string) {
  try {
    const cookieStore = await cookies();
    cookieStore.set(cookieName, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
      maxAge: 60 * 60 * 24 * 7, // 7 days
    });
  } catch (error) {
    logEvent("Setting auth cookie failed", "auth", { token }, "error", error);
    throw new Error("Failed to set auth cookie");
  }
}

// Get auth cookie
export async function getAuthCookie() {
  try {
    const cookieStore = await cookies();
    const token = cookieStore.get(cookieName);
    return token?.value;
  } catch (error) {
    logEvent("Getting auth cookie failed", "auth", {}, "error", error);
    return null;
  }
}

// remove auth cookie
export async function removeAuthCookie() {
  try {
    const cookieStore = await cookies();
    cookieStore.delete(cookieName);
  } catch (error) {
    logEvent("Removing auth cookie failed", "auth", {}, "error", error);
    throw new Error("Failed to remove auth cookie");
  }
}
