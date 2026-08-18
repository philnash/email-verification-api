export function createResolveTxtFixture(records: string[][]) {
  const calls: string[] = [];

  return {
    calls,
    resolveTxt: (target: string): Promise<string[][]> => {
      calls.push(target);
      return Promise.resolve(records);
    },
  };
}

type FetchRoute = Response | (() => Response | Promise<Response>);

export function createFetchFixture(
  routes: Readonly<Record<string, FetchRoute>>,
) {
  const calls: string[] = [];
  const inits: (RequestInit | undefined)[] = [];

  return {
    calls,
    inits,
    fetch: async (
      input: string | URL | Request,
      init?: RequestInit,
    ): Promise<Response> => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      calls.push(url);
      inits.push(init);
      const route = routes[url];
      if (route === undefined) {
        return new Response("not found", { status: 404 });
      }
      return typeof route === "function" ? route() : route;
    },
  };
}
