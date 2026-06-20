export class ToolipError extends Error {
  public readonly code: string;
  public readonly exitCode: number;

  constructor(message: string, options?: { code?: string; exitCode?: number }) {
    super(message);
    this.name = 'ToolipError';
    this.code = options?.code ?? 'TOOLIP_ERROR';
    this.exitCode = options?.exitCode ?? 1;
  }
}
