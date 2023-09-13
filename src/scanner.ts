export const findingSeverities: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  OTHER: 4,
  INFORMATIONAL: 4,
  UNTRIAGED: 4,
};

export type ScanFindings = {
  findingSeverityCounts?: Record<string, number>;
  errorMessage?: string;
};
