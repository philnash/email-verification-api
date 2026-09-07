# Next.js Email Verification API example

This application uses the [email-verification-api](https://www.npmjs.com/package/email-verification-api) package to implement the Email Verification API within a Next.js application.

> [!NOTE]
> While this is experimental, ensure you enable the [email-verification-protocol flag](chrome://flags/#email-verification-protocol) in Chrome settings.

## Running the app

First install the dependencies:

```sh
npm install
```

Copy the `.env.example` file to `.env`:

```sh
cp .env.example .env
```

Create a session secret and store it in `.env`.

```sh
openssl rand -base64 32
```

Run the application:

```sh
npm run dev
```

Open the app at http://localhost:3000/.

Ensure you are logged into Gmail, then enter your Gmail address in the email input.

## How it works

On every page load, the code in [proxy.ts](./proxy.ts) mints a fresh nonce and sets it in the session. This is added as a `nonce` attribute on a hidden `<input>` in [app/page.tsx](./app/page.tsx).

The form is submitted to [app/api/verify/route.ts](./app/api/verify/route.ts) where the email and token are extracted from the request, the nonce is extracted from the session, and the audience (the site URL) is created based on the request. Those details are then passed to `verifyEmailToken` which performs [the verification of the token as described by the Chrome blog here](https://developer.chrome.com/blog/email-verification-protocol-origin-trial#validate_the_evt).