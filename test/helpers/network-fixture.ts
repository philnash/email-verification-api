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
