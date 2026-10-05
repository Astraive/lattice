import type { ReactNode } from "react";

export type WebPageProps = {
  children: ReactNode;
  notice?: ReactNode;
  error?: ReactNode;
};
