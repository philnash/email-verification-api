import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Email Verification API Example",
  description: "An example of the email verification API built with Next.js.",
};

export default function RootLayout({ children }: LayoutProps<"/">) {
  return (
    <html lang="en" className={`h-full antialiased`}>
      <head>
        <meta
          httpEquiv="origin-trial"
          content="Ah9at3HZ3FacP7dBHylaXdHz3Y1G6IXdv5SNDuEEhmQwKmaBhWeJye16salX949px/izfNSaDZeE6wgGBZfJogcAAABqeyJvcmlnaW4iOiJodHRwczovL3ZlcmlmeWVtYWlscy52ZXJjZWwuYXBwOjQ0MyIsImZlYXR1cmUiOiJFbWFpbFZlcmlmaWNhdGlvblByb3RvY29sIiwiZXhwaXJ5IjoxNzk0ODczNjAwfQ=="
        />
      </head>
      <body className="min-h-full flex flex-col">{children}</body>
    </html>
  );
}
