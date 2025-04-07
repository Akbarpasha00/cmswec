import { NextResponse } from "next/server"
import type { NextRequest } from "next/server"
import { getToken } from "next-auth/jwt"
import { UserRole } from "./constants/roles"

export async function middleware(request: NextRequest) {
  const token = await getToken({ req: request, secret: process.env.NEXTAUTH_SECRET })
  const pathname = request.nextUrl.pathname

  // Allow public routes
  if (
    pathname === "/login" ||
    pathname === "/" ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/api/auth") ||
    pathname.startsWith("/favicon.ico") ||
    pathname.startsWith("/images")
  ) {
    return NextResponse.next()
  }

  // Check if user is authenticated
  if (!token) {
    const url = new URL("/login", request.url)
    url.searchParams.set("callbackUrl", pathname)
    url.searchParams.set("error", "SessionRequired")
    return NextResponse.redirect(url)
  }

  // Check if user is admin
  const userRole = token.role as string

  if (userRole !== UserRole.ADMIN) {
    // Redirect non-admin users to login
    const url = new URL("/login", request.url)
    url.searchParams.set("error", "AdminAccessRequired")
    return NextResponse.redirect(url)
  }

  return NextResponse.next()
}

export const config = {
  matcher: ["/((?!api/auth|_next/static|_next/image|favicon.ico).*)"],
}

