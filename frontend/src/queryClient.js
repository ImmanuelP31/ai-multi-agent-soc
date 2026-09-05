import { QueryClient } from "@tanstack/react-query";

export function createQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: {
        staleTime: 10000,
        retry: 1,
        refetchOnWindowFocus: false,
      },
    },
  });
}

const queryClient = createQueryClient();

export default queryClient;
