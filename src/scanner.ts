export const findingSeverities: Record<string, number> = {
  CRITICAL: 0,
  HIGH: 1,
  MEDIUM: 2,
  LOW: 3,
  INFORMATIONAL: 4,
};

export type ScanFindings = {
  findingSeverityCounts?: Record<string, number>;
  errorMessage?: string;
};
