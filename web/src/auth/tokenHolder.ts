/**
 * Holds the current token for the API client. The client reads it when a
 * request is made, so it always sends the token of the latest session even
 * though it is created only once.
 */
export class TokenHolder {
  private value: string | null

  constructor(initial: string | null) {
    this.value = initial
  }

  get(): string | null {
    return this.value
  }

  set(token: string | null): void {
    this.value = token
  }
}
