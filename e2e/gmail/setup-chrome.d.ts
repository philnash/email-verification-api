export function chromeArguments(profileDirectory: string): string[];

export function chromeDebugArguments(
  profileDirectory: string,
  startUrl: string,
  debuggingPort: number,
): string[];

export function chromeExecutable(
  platform: NodeJS.Platform,
  environment: NodeJS.ProcessEnv,
): string;
