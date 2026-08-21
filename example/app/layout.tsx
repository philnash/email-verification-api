import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Email Verification API Example",
  description: "An example of the email verification API built with Next.js.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html
      lang="en"
      className={`h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
