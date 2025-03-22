"use server";
import { auth, db } from "@/firebase/admin";
import { cookies } from "next/headers";

// Session duration (1 week)
const SESSION_DURATION = 60 * 60 * 24 * 7;

export async function signUp(params: SignUpParams) {
  const { uid, name, email } = params;

  try {
    const userRecord = await db.collection("users").doc(uid).get();

    if (userRecord.exists) {
      return {
        success: false,
        message: "User already exists. Please sign in instead.",
      };
    }

    await db.collection("users").doc(uid).set({
      name,
      email,
    });

    return {
      success: true,
      message: "Account created successfully. Please sign in.",
    };
  } catch (e: any) {
    console.error(`Error creating a user`, e);

    if (
      e.code === "auth/email-already-exists" ||
      e.code === "auth/email-already-in-use"
    ) {
      return {
        success: false,
        message: "This email is already in use.",
      };
    }

    return {
      success: false,
      message: "Failed to create an account",
    };
  }
}

export async function signIn(params: SignInParams) {
  const { email, idToken } = params;

  try {
    const userRecord = await auth.getUserByEmail(email);

    if (!userRecord) {
      return {
        success: false,
        message: "User does not exist. Create an account instead.",
      };
    }

    console.log("Set session cookie");

    await setSessionCookie(idToken);
  } catch (e) {
    console.log(e);

    return {
      success: false,
      message: "Failed to log into an account.",
    };
  }
}

export async function setSessionCookie(idToken: string) {
  const cookieStore = await cookies();

  console.log(`set session cookie idtoken ${idToken}`);

  const sessionCookie = await auth.createSessionCookie(idToken, {
    expiresIn: SESSION_DURATION * 1000,
  });

  cookieStore.set("session", sessionCookie, {
    maxAge: SESSION_DURATION,
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    path: "/",
    sameSite: "lax",
  });
}

export async function getCurrentUser(): Promise<User | null> {
  const cookieStore = await cookies();

  const sessionCookie = cookieStore.get("session")?.value;

  console.log(`sessionCookie ${sessionCookie}`);
  if (!sessionCookie) return null;

  try {
    const decodedClaims = await auth.verifySessionCookie(sessionCookie, true);

    console.log(`decodedClaims: `, decodedClaims);
    const userRecord = await db
      .collection("users")
      .doc(decodedClaims.uid)
      .get();

    console.log(`userRecord: `, userRecord);
    console.log(`decodedClaims: `, decodedClaims.uid);
    console.log(`userRecord.exists: `, userRecord.exists);
    console.log(`userRecord.data: `, userRecord.data());

    if (!userRecord.exists) {
      console.log(`User does not exist`);
      return null;
    }

    return {
      ...userRecord.data(),
      id: userRecord.id,
    } as User;
  } catch (e) {
    console.log(e);

    return null;
  }
}

export async function isAuthenticated() {
  const user = await getCurrentUser();

  return !!user;
}
