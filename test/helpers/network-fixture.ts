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

  return {
    calls,
    fetch: async (input: string | URL | Request): Promise<Response> => {
      const url =
        typeof input === "string"
          ? input
          : input instanceof URL
            ? input.href
            : input.url;
      calls.push(url);
      const route = routes[url];
      if (route === undefined) {
        return new Response("not found", { status: 404 });
      }
      return typeof route === "function" ? route() : route;
    },
  };
}
