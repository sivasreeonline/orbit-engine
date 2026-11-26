export class DatabaseUnavailableError extends Error {
  constructor() {
    super("database_unavailable");
    this.name = "DatabaseUnavailableError";
  }
}
