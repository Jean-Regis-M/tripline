export interface ToolDef { name: string; description: string; title?: string; inputSchema?: Record<string, any>; outputSchema?: Record<string, any>; annotations?: Record<string, any> }
export interface ServerManifest { name: string; tools: ToolDef[] }
export interface Manifest { servers: ServerManifest[] }
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export interface Finding { rule: string; severity: Severity; server: string; tool: string; title: string; evidence?: string }
export interface ScanReport { findings: Finding[]; verdict: 'block' | 'review' | 'pass'; risk: Record<string, number> }
