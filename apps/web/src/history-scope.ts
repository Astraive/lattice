export type ScopedHistory<T> = {
  scope: string;
  messages: T[];
  loading: boolean;
} | null;

export function messagesForScope<T>(scope: string, history: ScopedHistory<T>): T[] {
  return history?.scope === scope ? history.messages : [];
}
